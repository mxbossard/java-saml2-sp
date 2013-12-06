/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */

package fr.mby.saml2.sp.impl.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.config.IIdpConfig;
import fr.mby.saml2.sp.api.config.IWayfConfig;
import fr.mby.saml2.sp.api.core.ISaml20IdpConnector;
import fr.mby.saml2.sp.api.core.SamlBindingEnum;
import fr.mby.saml2.sp.opensaml.helper.OpenSamlHelper;

/**
 * This implementation retrieve the current HTTP Request from Spring webflow context.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class BasicIdpConfig implements IIdpConfig, InitializingBean {

	/** Logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(BasicIdpConfig.class);

	/** SVUID. */
	private static final long serialVersionUID = -3392368326559269830L;

	/** IdP config id. */
	private String id;

	/** IdP connector. */
	private transient ISaml20IdpConnector saml20IdpConnector;

	/** IdP description. */
	private String description;

	/** IdP picture URL. */
	private String pictureUrl;

	/** Force IdP authentication. */
	private boolean forceAuthentication = true;

	/** Time window in ms durint which the request are valids (by default 300000ms means requests are valid +-300000ms). */
	private long timeValidityWindow = 300000;

	/** Response binding wanted. Default HTTP-POST. */
	private SamlBindingEnum responseBinding = SamlBindingEnum.SAML_20_HTTP_POST;

	/** Request binding wanted. Default HTTP-Redirect. */
	private SamlBindingEnum requestBinding = SamlBindingEnum.SAML_20_HTTP_REDIRECT;

	/** The index of Attribute consuming service wanted. */
	private Integer attributeConsumingServiceIndex = 1;

	/** IdP entity ID (same in metadata file). */
	private String idpEntityId;

	/** Used to verify signature responses and encrypt assertions. */
	private transient Resource idpMetadata;

	/** IdP metadata provider. */
	private transient MetadataProvider idpMetadataProvider;

	/** Verify the IdP Signatures via metadata. */
	private transient SignatureTrustEngine signatureTrustEngine;

	/** IdP Endpoints URL for SSO. */
	private final Map<SamlBindingEnum, String> idpSsoEndpointUrl = new HashMap<SamlBindingEnum, String>();

	/** Idp endpoints URL for Single Logout. */
	private final Map<SamlBindingEnum, String> idpSloEndpointUrl = new HashMap<SamlBindingEnum, String>();

	/** Global Wayf Config. */
	private IWayfConfig wayfConfig;

	@Override
	public String getIdpSsoEndpointUrl(final SamlBindingEnum binding) {
		return this.idpSsoEndpointUrl.get(binding);
	}

	@Override
	public String getIdpSloEndpointUrl(final SamlBindingEnum binding) {
		return this.idpSloEndpointUrl.get(binding);
	}

	/**
	 * Build a signature trust engine based on a metadata provider.
	 * 
	 * @param metadataProvider
	 *            the metadata provider
	 * @return the signature trust engine
	 */
	protected SignatureTrustEngine buildSignatureTrustEngine(final MetadataProvider metadataProvider) {
		SignatureTrustEngine signatureTrustEngine = null;

		if (metadataProvider != null) {
			final MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver(metadataProvider);
			final KeyInfoCredentialResolver keyInfoCredResolver = Configuration.getGlobalSecurityConfiguration()
					.getDefaultKeyInfoCredentialResolver();
			signatureTrustEngine = new ExplicitKeySignatureTrustEngine(mdCredResolver, keyInfoCredResolver);
		}

		return signatureTrustEngine;
	}

	/**
	 * Process IdP metadatas.
	 * 
	 * @throws MetadataProviderException
	 * @throws XMLParserException
	 * @throws ConfigurationException
	 */
	protected void processIdpMetadata() throws MetadataProviderException, XMLParserException, ConfigurationException {
		BasicIdpConfig.LOGGER.debug("Precessing metadata of IdP with Id: [{}]...", this.id);

		DefaultBootstrap.bootstrap();

		this.idpMetadataProvider = OpenSamlHelper.buildMetadataProvider(this.idpMetadata);
		Assert.notNull(this.idpMetadataProvider, "IdP metadata provider wasn't build !");
		BasicIdpConfig.LOGGER.debug("IdP metadata provider ref: [{}].", this.idpMetadataProvider);

		this.signatureTrustEngine = this.buildSignatureTrustEngine(this.idpMetadataProvider);
		Assert.notNull(this.signatureTrustEngine, "Signature trust engine wasn't build !");
		BasicIdpConfig.LOGGER.debug("IdP signature trust engine ref: [{}].", this.signatureTrustEngine);

		final EntityDescriptor idpEntityDescriptor = this.idpMetadataProvider.getEntityDescriptor(this.idpEntityId);
		Assert.notNull(idpEntityDescriptor,
				String.format("No entity descriptor found in IdP metadata for IdP entityId [%s]", this.idpEntityId));
		BasicIdpConfig.LOGGER.debug("IdP entity descriptor ref: [{}].", idpEntityDescriptor);

		final IDPSSODescriptor ssoDescriptors = idpEntityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
		if (ssoDescriptors != null) {
			// Retrieve SSO endpoints URL.
			final List<SingleSignOnService> ssoServices = ssoDescriptors.getSingleSignOnServices();
			if (!CollectionUtils.isEmpty(ssoServices)) {
				for (final SingleSignOnService ssoService : ssoServices) {
					if ((ssoService != null)) {
						final SamlBindingEnum binding = SamlBindingEnum.fromSamlUri(ssoService.getBinding());
						if (binding != null) {
							this.idpSsoEndpointUrl.put(binding, ssoService.getLocation());
						}
					}
				}
			}

			// Retrieve Single Logout endpoints URL.
			final List<SingleLogoutService> slServices = ssoDescriptors.getSingleLogoutServices();
			if (!CollectionUtils.isEmpty(slServices)) {
				for (final SingleLogoutService slService : slServices) {
					if ((slService != null)) {
						final SamlBindingEnum binding = SamlBindingEnum.fromSamlUri(slService.getBinding());
						if (binding != null) {
							this.idpSloEndpointUrl.put(binding, slService.getLocation());
						}
					}
				}
			}
		}

		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			if (!StringUtils.hasText(this.idpSsoEndpointUrl.get(binding))) {
				BasicIdpConfig.LOGGER.warn(String.format(
						"No SSO %s endpoint URL found in metadata for the [%s] IdP connector !",
						binding.getDescription(), this.getIdpEntityId()));
			};
		}

		for (final SamlBindingEnum binding : SamlBindingEnum.values()) {
			if (!StringUtils.hasText(this.idpSloEndpointUrl.get(binding))) {
				BasicIdpConfig.LOGGER.warn(String.format(
						"No SLO %s endpoint URL found in metadata for the [%s] IdP connector !",
						binding.getDescription(), this.getIdpEntityId()));
			}
		}

		BasicIdpConfig.LOGGER.debug("IdP registered SSO endpoint URL: [{}]", this.idpSsoEndpointUrl);
		BasicIdpConfig.LOGGER.debug("IdP registered SLO endpoint URL: [{}]", this.idpSloEndpointUrl);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.id, "No id provided for this IdP config !");
		Assert.isTrue(StringUtils.hasText(this.idpEntityId),
				String.format("No IdP EntityId provided for IdP config with id [%s] !", this.id));

		Assert.isTrue((this.idpMetadata != null) && this.idpMetadata.exists(),
				String.format("No IdP metadata provided for IdP config with id [%s]!", this.id));

		this.processIdpMetadata();
	}

	@Override
	public ISaml20IdpConnector getSaml20IdpConnector() {
		return this.saml20IdpConnector;
	}

	@Override
	public void registerSaml20IdpConnector(final ISaml20IdpConnector saml20IdpConnector) {
		this.saml20IdpConnector = saml20IdpConnector;
	}

	@Override
	public SignatureTrustEngine getSignatureTrustEngine() {
		return this.signatureTrustEngine;
	}

	@Override
	public String getId() {
		return this.id;
	}

	public void setId(final String id) {
		this.id = id;
	}

	@Override
	public String getDescription() {
		return this.description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	@Override
	public String getPictureUrl() {
		return this.pictureUrl;
	}

	public void setPictureUrl(final String pictureUrl) {
		this.pictureUrl = pictureUrl;
	}

	@Override
	public IWayfConfig getWayfConfig() {
		return this.wayfConfig;
	}

	@Override
	public void registerWayfConfig(final IWayfConfig wayfConfig) {
		this.wayfConfig = wayfConfig;
	}

	@Override
	public Integer getAttributeConsumingServiceIndex() {
		return this.attributeConsumingServiceIndex;
	}

	public void setAttributeConsumingServiceIndex(final Integer attributeConsumingServiceIndex) {
		this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
	}

	@Override
	public boolean isForceAuthentication() {
		return this.forceAuthentication;
	}

	public void setForceAuthentication(final boolean forceAuthentication) {
		this.forceAuthentication = forceAuthentication;
	}

	@Override
	public SamlBindingEnum getResponseBinding() {
		return this.responseBinding;
	}

	public void setResponseBinding(final SamlBindingEnum responseBinding) {
		this.responseBinding = responseBinding;
	}

	@Override
	public SamlBindingEnum getRequestBinding() {
		return this.requestBinding;
	}

	public void setRequestBinding(final SamlBindingEnum requestBinding) {
		this.requestBinding = requestBinding;
	}

	@Override
	public long getTimeValidityWindow() {
		return this.timeValidityWindow;
	}

	/**
	 * Time window in ms durint which the request are valids (by default 300000ms means requests are valid +-300000ms).
	 * 
	 * @param timeValidityWindow
	 *            the time validity window
	 */
	public void setTimeValidityWindow(final long timeValidityWindow) {
		this.timeValidityWindow = timeValidityWindow;
	}

	@Override
	public String getIdpEntityId() {
		return this.idpEntityId;
	}

	public void setIdpEntityId(final String idpEntityId) {
		this.idpEntityId = idpEntityId;
	}

	@Override
	public Resource getIdpMetadata() {
		return this.idpMetadata;
	}

	public void setIdpMetadata(final Resource idpMetadata) {
		this.idpMetadata = idpMetadata;
	}

}

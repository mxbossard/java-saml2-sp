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

package fr.mby.saml2.sp.impl.core;

import java.io.IOException;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import fr.mby.saml2.sp.api.core.ISaml20Storage;
import fr.mby.saml2.sp.api.om.IAuthentication;

/**
 * Facade for CAS SAML 2.0 usage
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
@Repository
public class EhcacheSaml20Storage implements ISaml20Storage, InitializingBean {

	/** SAML 2.0 Authentication credentials cache name. */
	public static final String SAML2_AUTH_CREDS_CACHE_NAME = "saml2AuthCredsCache";

	/** SAML 2.0 Authentication Base ID cache name. */
	private static final String SAML2_BASE_ID_CACHE_NAME = "saml2BaseIdCache";

	/** SAML 2.0 Authentication Name ID cache name. */
	private static final String SAML2_NAME_ID_CACHE_NAME = "saml2NameIdCache";

	/** SAML 2.0 Authentication credentials cache. */
	private Ehcache saml2AuthenticatedCredentialsCache;

	/** SAML 2.0 Authentication Name ID cache. */
	private Ehcache saml2NameIdCache;

	/** SAML 2.0 Authentication Base ID cache. */
	private Ehcache saml2BaseIdCache;

	@Override
	public void storeAuthenticationInCache(final String tgtId, final IAuthentication auth) {
		if (StringUtils.hasText(tgtId) && (auth != null)) {
			if (this.saml2AuthenticatedCredentialsCache.isKeyInCache(tgtId)) {
				// TGT already used !
				throw new IllegalStateException(
						String.format(
								"Unable to store SAML 2.0 authenticated credentials in cache beacause TGT [%s] is already present !",
								tgtId));
			}
			this.saml2AuthenticatedCredentialsCache.put(new Element(tgtId, auth));

			final String idpSubject = auth.getSubjectId();
			if (StringUtils.hasText(idpSubject)) {
				this.saml2NameIdCache.put(new Element(idpSubject, tgtId));
			}
		}
	}

	@Override
	public IAuthentication retrieveAuthenticationFromCache(final String tgtId) {
		IAuthentication auth = null;

		if (StringUtils.hasText(tgtId)) {
			final Element element = this.saml2AuthenticatedCredentialsCache.get(tgtId);
			if (element != null) {
				final Object value = element.getValue();
				if (value != null) {
					auth = (IAuthentication) value;
				}
			}
		}

		return auth;
	}

	@Override
	public IAuthentication removeAuthenticationFromCache(final String tgtId) {
		final IAuthentication auth = this.retrieveAuthenticationFromCache(tgtId);

		if (StringUtils.hasText(tgtId)) {
			this.saml2AuthenticatedCredentialsCache.remove(tgtId);
		}

		if (auth != null) {
			final String idpSubject = auth.getSubjectId();
			if (StringUtils.hasText(idpSubject)) {
				this.saml2NameIdCache.remove(idpSubject);
			}
		}

		return auth;
	}

	/**
	 * Initialize caches if needed.
	 * 
	 * @throws IOException
	 * @throws CacheException
	 */
	protected void initCache() throws CacheException, IOException {
		if (this.saml2AuthenticatedCredentialsCache == null) {
			final EhCacheFactoryBean cacheFactory = new EhCacheFactoryBean();
			cacheFactory.setCacheName(EhcacheSaml20Storage.SAML2_AUTH_CREDS_CACHE_NAME);
			cacheFactory.afterPropertiesSet();
			this.saml2AuthenticatedCredentialsCache = cacheFactory.getObject();
		}
		this.saml2AuthenticatedCredentialsCache.bootstrap();

		if (this.saml2BaseIdCache == null) {
			final EhCacheFactoryBean cacheFactory = new EhCacheFactoryBean();
			cacheFactory.setCacheName(EhcacheSaml20Storage.SAML2_BASE_ID_CACHE_NAME);
			cacheFactory.afterPropertiesSet();
			this.saml2BaseIdCache = cacheFactory.getObject();
		}
		this.saml2BaseIdCache.bootstrap();

		if (this.saml2NameIdCache == null) {
			final EhCacheFactoryBean cacheFactory = new EhCacheFactoryBean();
			cacheFactory.setCacheName(EhcacheSaml20Storage.SAML2_NAME_ID_CACHE_NAME);
			cacheFactory.afterPropertiesSet();
			this.saml2NameIdCache = cacheFactory.getObject();
		}
		this.saml2NameIdCache.bootstrap();
	}

	@Override
	public String findSessionIndexBySamlNameId(final String nameId) {
		String tgtId = null;

		if (StringUtils.hasText(nameId)) {
			final Element element = this.saml2NameIdCache.get(nameId);
			if (element != null) {
				tgtId = (String) element.getValue();
			}
		}

		return tgtId;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		this.initCache();
	}

	public Ehcache getSaml2AuthenticatedCredentialsCache() {
		return this.saml2AuthenticatedCredentialsCache;
	}

	public void setSaml2AuthenticatedCredentialsCache(final Ehcache saml2AuthenticatedCredentialsCache) {
		this.saml2AuthenticatedCredentialsCache = saml2AuthenticatedCredentialsCache;
	}

	public Ehcache getSaml2NameIdCache() {
		return this.saml2NameIdCache;
	}

	public void setSaml2NameIdCache(final Ehcache saml2NameIdCache) {
		this.saml2NameIdCache = saml2NameIdCache;
	}

	public Ehcache getSaml2BaseIdCache() {
		return this.saml2BaseIdCache;
	}

	public void setSaml2BaseIdCache(final Ehcache saml2BaseIdCache) {
		this.saml2BaseIdCache = saml2BaseIdCache;
	}

}

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
package fr.mby.saml2.sp.impl.helper;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.Resource;

/**
 * Helper for security manipulation.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SecurityHelper {

	/** Logger. */
	@SuppressWarnings("unused")
	private static final Log LOGGER = LogFactory.getLog(SecurityHelper.class);

	/** Hidden constructor. */
	private SecurityHelper() {

	}

	/**
	 * Build a certificate from PEM resource.
	 * 
	 * @param certificate the PEM resource
	 * @param type the certificate type
	 * @return the java.security.cert.Certificate
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static Certificate buildCertificate(final Resource certificate, final String type) throws CertificateException, IOException {
		Certificate result = null;

		CertificateFactory certFactory = CertificateFactory.getInstance(type);
		result = certFactory.generateCertificate(certificate.getInputStream());

		return result;
	}

	/**
	 * Build a private Key from DER resource.
	 * 
	 * @param certificate the DER resource
	 * @param pkSpecClass the java key specification class
	 * @param type the certificate type
	 * @return the java.security.cert.Certificate
	 * @throws NoSuchMethodException
	 * @throws SecurityException
	 * @throws InvocationTargetException
	 * @throws IllegalAccessException
	 * @throws InstantiationException
	 * @throws IllegalArgumentException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public static PrivateKey buildPrivateKey(final Resource privateKey, final Class<EncodedKeySpec> pkSpecClass, final String type) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		PrivateKey result = null;

		Constructor<EncodedKeySpec> keySpecConstructor = pkSpecClass.getConstructor(byte[].class);
		byte[] keyBytes = SecurityHelper.readBytesFromFilePath(privateKey);
		if (keyBytes != null) {
			EncodedKeySpec keySpec = keySpecConstructor.newInstance(keyBytes);
			KeyFactory pkFactory = KeyFactory.getInstance(type);
			result = pkFactory.generatePrivate(keySpec);
		}

		return result;
	}

	public static byte[] readBytesFromFilePath(final Resource resource) throws IOException {
		byte[] keyBytes = null;

		InputStream keyStream = resource.getInputStream();
		keyBytes = IOUtils.toByteArray(keyStream);

		return keyBytes;
	}
}

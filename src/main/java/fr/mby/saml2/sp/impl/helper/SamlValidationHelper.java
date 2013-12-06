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

import org.joda.time.DateTime;
import org.joda.time.Instant;

import fr.mby.saml2.sp.api.exception.SamlValidationException;

/**
 * SAML Validation helper.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class SamlValidationHelper {

	/**
	 * Validate times notBefore and notOnOrAfter conditions.
	 * 
	 * @param clockSkewSeconds allowed time shift
	 * @param notBefore notBefore condition
	 * @param notOnOrAfter notOnOrAfter condition
	 * @throws SamlValidationException
	 *             in case of validation problem.
	 */
	public static void validateTimes(final int clockSkewSeconds, final DateTime notBefore,
			final DateTime notOnOrAfter) throws SamlValidationException {
		Instant serverInstant = new Instant();

		if (notBefore != null) {
			// Instant with skew
			Instant notBeforeInstant = notBefore.toInstant().withDurationAdded(clockSkewSeconds * 1000, -1);

			if (serverInstant.isBefore(notBeforeInstant)) {
				throw new SamlValidationException(
						"SAML 2.0 Message is outdated (too early) !");
			}
		}

		if ((notOnOrAfter != null)) {
			// Instant with skew
			Instant notOrOnAfterInstant = notOnOrAfter.toInstant().withDurationAdded(
					(clockSkewSeconds * 1000) - 1, 1);

			if (serverInstant.isAfter(notOrOnAfterInstant)) {
				throw new SamlValidationException(
						"SAML 2.0 Message is outdated (too late) !");
			}
		}

	}

}

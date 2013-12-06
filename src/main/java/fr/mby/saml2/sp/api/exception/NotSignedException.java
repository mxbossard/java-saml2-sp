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
package fr.mby.saml2.sp.api.exception;

/**
 * Indicate an absence of signature.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class NotSignedException extends Exception {

	/** SVUID. */
	private static final long serialVersionUID = -6526199098196184344L;

	public NotSignedException() {
		super();
	}

	public NotSignedException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public NotSignedException(final String message) {
		super(message);
	}

	public NotSignedException(final Throwable cause) {
		super(cause);
	}

}

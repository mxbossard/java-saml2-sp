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
 * Error throwed if an unsuported SAML operation or feature is encountered.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class UnsupportedSamlOperation extends Exception {

	/** Svuid. */
	private static final long serialVersionUID = -5645234584904167672L;

	public UnsupportedSamlOperation() {
		super();
	}

	public UnsupportedSamlOperation(final String arg0) {
		super(arg0);
	}

	public UnsupportedSamlOperation(final Throwable arg0) {
		super(arg0);
	}

	public UnsupportedSamlOperation(final String arg0, final Throwable arg1) {
		super(arg0, arg1);
	}

}

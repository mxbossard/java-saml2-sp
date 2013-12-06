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
package fr.mby.saml2.sp.api.query.engine;

import javax.servlet.http.HttpServletRequest;


import fr.mby.saml2.sp.api.core.ISaml20SpProcessor;
import fr.mby.saml2.sp.api.exception.SamlProcessingException;
import fr.mby.saml2.sp.api.exception.UnsupportedSamlOperation;

/**
 * Query Processor Factory. (Abstract Factory pattern).
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface IQueryProcessorFactory {

	/**
	 * Build the QueryProcessor wich is able to process the incoming request.
	 * 
	 * @param spProcessor the SP Processor in charge
	 * @param request HTTP request containing SAML message
	 * @return the query processor
	 * @throws UnsupportedSamlOperation
	 * @throws SamlProcessingException
	 */
	IQueryProcessor buildQueryProcessor(ISaml20SpProcessor spProcessor, HttpServletRequest request)
			throws UnsupportedSamlOperation, SamlProcessingException;

}

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
package fr.mby.saml2.sp.opensaml.wrapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;

/**
 * Spring resource wrapper to an open saml resource.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SpringResourceWrapper implements Resource {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(SpringResourceWrapper.class);

	/** Spring resource. */
	private org.springframework.core.io.Resource springResource;

	/**
	 * Constructor.
	 * 
	 * @param resource the spring resource to wrap.
	 */
	public SpringResourceWrapper(final org.springframework.core.io.Resource resource) {
		this.springResource = resource;
		
	}

	@Override
	public String getLocation() {
		String location = null;

		try {
			if (springResource.exists()) {
				location = new File(this.springResource.getURL().getFile()).getCanonicalPath();
			}
		} catch (IOException e) {
			// Do nothing
			SpringResourceWrapper.LOGGER.debug("It's not a file !", e);
		}
		if (location == null) {
			try {
				location = this.springResource.getURI().getPath();
			} catch (IOException e) {
				// Do nothing
				SpringResourceWrapper.LOGGER.debug("It's not an URI ether !", e);
			}
		}

		if (location == null) {
			try {
				location = this.springResource.getURL().getPath();
			} catch (IOException e) {
				// Do nothing
				SpringResourceWrapper.LOGGER.debug("It's not an URL ether !", e);
			}
		}

		return location;
	}

	@Override
	public boolean exists() throws ResourceException {
		return this.springResource.exists();
	}

	@Override
	public InputStream getInputStream() throws ResourceException {
		try {
			return this.springResource.getInputStream();
		} catch (IOException e) {
			throw new ResourceException(e);
		}
	}

	@Override
	public DateTime getLastModifiedTime() throws ResourceException {
		try {
			long time = this.springResource.lastModified();
			return new DateTime(time);
		} catch (IOException e) {
			throw new ResourceException(e);
		}
	}

}

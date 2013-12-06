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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.springframework.util.Assert;

import fr.mby.saml2.sp.impl.helper.SamlHelper;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=BlockJUnit4ClassRunner.class)
public class SamlHelperTest {

	private static final String REDIRECT_BIND_SAML_REQUEST = "fZJdT4MwFIav9VeQ3vM5ZFsDJNPFuGS6ZaAX3pjSnY0m0GJPMfPfC2zGeUMv 2zfP0/O2MbK6auiiNaXcwWcLaKxTXUmkw0FCWi2pYiiQSlYDUsNptnhe08Dx aKOVUVxVxFoggjZCyQclsa1BZ6C/BIfX3TohpTENUtfdQ61skMY5ikYDF8xR +uhmpSgKVYEpHUTl9vDA3W6ynFjL7jZCsp77R4GT0UyCcRi3la6ASbSNajU6 B+0OhGxDrNUyIR8Q+pyFwWw2DSd+NJ/dHaaTeRhFXsB5VMC8iyG2sJJomDQJ CTw/sL2p7U1yP6DhlPrRO7G2lynvhdwLeRyvpDiHkD7l+dY+j/EGGocRugBJ b2+GFff90sGvrxofp7Pfmkk6XipnGLtXhos1Pr/2SwdeLbeqEvzbelS6Zmbc 2++IvX0YorTvH0XnJG56tvz/QOkP";

	@Test
	public void decodeRedirectBindSamlRequest() throws Exception {
		String decodedRequest = SamlHelper.httpRedirectDecode(SamlHelperTest.REDIRECT_BIND_SAML_REQUEST);

		Assert.notNull(decodedRequest, "Decoded request is null !");

		System.out.println(decodedRequest);
	}

}

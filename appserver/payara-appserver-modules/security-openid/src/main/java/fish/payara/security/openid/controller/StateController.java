/*
 *  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 *  Copyright (c) [2018-2021] Payara Foundation and/or its affiliates. All rights reserved.
 *
 *  The contents of this file are subject to the terms of either the GNU
 *  General Public License Version 2 only ("GPL") or the Common Development
 *  and Distribution License("CDDL") (collectively, the "License").  You
 *  may not use this file except in compliance with the License.  You can
 *  obtain a copy of the License at
 *  https://github.com/payara/Payara/blob/master/LICENSE.txt
 *  See the License for the specific
 *  language governing permissions and limitations under the License.
 *
 *  When distributing the software, include this License Header Notice in each
 *  file and include the License file at glassfish/legal/LICENSE.txt.
 *
 *  GPL Classpath Exception:
 *  The Payara Foundation designates this particular file as subject to the "Classpath"
 *  exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 *  file that accompanied this code.
 *
 *  Modifications:
 *  If applicable, add the following below the License Header, with the fields
 *  enclosed by brackets [] replaced by your own identifying information:
 *  "Portions Copyright [year] [name of copyright owner]"
 *
 *  Contributor(s):
 *  If you wish your version of this file to be governed by only the CDDL or
 *  only the GPL Version 2, indicate your decision by adding "[Contributor]
 *  elects to include this software in this distribution under the [CDDL or GPL
 *  Version 2] license."  If you don't indicate a single choice of license, a
 *  recipient has the option to distribute your version of this file under
 *  either the CDDL, the GPL Version 2 or to extend the choice of license to
 *  its licensees as provided above.  However, if you add GPL Version 2 code
 *  and therefore, elected the GPL Version 2 license, then the option applies
 *  only if the new code is made subject to such option by the copyright
 *  holder.
 */
package fish.payara.security.openid.controller;

import static fish.payara.security.openid.OpenIdUtil.not;
import fish.payara.security.openid.api.OpenIdState;
import fish.payara.security.openid.domain.OpenIdConfiguration;
import static fish.payara.security.openid.http.HttpStorageController.getInstance;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import org.glassfish.common.util.StringHelper;

import java.util.Optional;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Controller to manage OpenId state parameter value
 *
 * @author Gaurav Gupta
 */
@ApplicationScoped
public class StateController {

    private static final String STATE_KEY = "oidc.state";

    public void store(
            OpenIdState state,
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        getInstance(configuration, request, response)
                .store(STATE_KEY, state.getValue(), null);
    }

    public Optional<OpenIdState> get(
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        return getInstance(configuration, request, response)
                .getAsString(STATE_KEY)
                .filter(not(StringHelper::isEmpty))
                .map(OpenIdState::new);
    }

    public void remove(
            OpenIdConfiguration configuration,
            HttpServletRequest request,
            HttpServletResponse response) {

        getInstance(configuration, request, response)
                .remove(STATE_KEY);
    }
}

/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) [2018-2021] Payara Foundation and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://github.com/payara/Payara/blob/master/LICENSE.txt
 * See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * The Payara Foundation designates this particular file as subject to the "Classpath"
 * exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package fish.payara.microprofile.healthcheck.servlet;

import static fish.payara.microprofile.Constants.CREATE_INSECURE_ENDPOINT_TEST;
import static java.util.Arrays.asList;
import static jakarta.servlet.annotation.ServletSecurity.TransportGuarantee.CONFIDENTIAL;
import static org.glassfish.common.util.StringHelper.isEmpty;

import java.util.Map;
import java.util.Set;

import jakarta.servlet.HttpConstraintElement;
import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.ServletSecurityElement;
import org.glassfish.internal.api.Globals;

import fish.payara.microprofile.healthcheck.config.MicroprofileHealthCheckConfiguration;

/**
 * Servlet Container Initializer that registers the HealthCheckServlet, as well
 * as the HealthChecks of a deployed application.
 *
 * @author Andrew Pielage
 */
public class HealthCheckServletContainerInitializer implements ServletContainerInitializer {

    @Override
    public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {
        // Check if this context is the root one ("/")
        if (ctx.getContextPath().isEmpty()) {
            // Check if there is already a servlet for healthcheck
            Map<String, ? extends ServletRegistration> registrations = ctx.getServletRegistrations();
            MicroprofileHealthCheckConfiguration configuration = Globals.getDefaultHabitat().getService(MicroprofileHealthCheckConfiguration.class);

            if (!Boolean.parseBoolean(configuration.getEnabled())) {
                return; //MP Healthcheck disabled
            }

            for (ServletRegistration reg : registrations.values()) {
                if (reg.getClass().equals(HealthCheckServlet.class) || reg.getMappings().contains("/" + configuration.getEndpoint())) {
                    return;
                }
            }

            String virtualServers = configuration.getVirtualServers();
            if (!isEmpty(virtualServers)
                    && !asList(virtualServers.split(",")).contains(ctx.getVirtualServerName())) {
                return;
            }

            // Register servlet
            ServletRegistration.Dynamic reg = ctx.addServlet("microprofile-healthcheck-servlet", HealthCheckServlet.class);
            reg.addMapping("/" + configuration.getEndpoint() + "/*");
            if (Boolean.parseBoolean(configuration.getSecurityEnabled())) {
                String[] roles = configuration.getRoles().split(",");
                reg.setServletSecurity(new ServletSecurityElement(new HttpConstraintElement(CONFIDENTIAL, roles)));
                ctx.declareRoles(roles);
                if (Boolean.getBoolean(CREATE_INSECURE_ENDPOINT_TEST)) {
                    ServletRegistration.Dynamic insecureReg = ctx
                            .addServlet("microprofile-healthcheck-servlet-insecure", HealthCheckServlet.class);
                    insecureReg.addMapping("/" + configuration.getEndpoint() + "-insecure/*");
                }
            }
        }
    }

}

package com.sun.enterprise.security;

import java.lang.reflect.Method;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.Arrays;
import javassist.util.proxy.MethodHandler;

public class AuthenticationProxyHandler implements MethodHandler {

    public final static Method impliesMethod = getMethod(
            Policy.class, "implies", ProtectionDomain.class, Permission.class);

    private final Policy javaSePolicy;

    public AuthenticationProxyHandler(Policy javaSePolicy) {
        this.javaSePolicy = javaSePolicy;
    }

    @Override
    public Object invoke(Object self, Method overridden, Method forwarder, Object[] args) throws Throwable {
        if (isImplementationOf(overridden, impliesMethod)) {
            Permission permission = (Permission) args[1];
            ProtectionDomain domain = (ProtectionDomain) args[0];
            if (!permission.getClass().getName().startsWith("jakarta.")) {
                return javaSePolicy.implies(domain, permission);
            }
        }

        return forwarder.invoke(self, args);
    }

    public static boolean isImplementationOf(Method implementationMethod, Method interfaceMethod) {
        return interfaceMethod.getDeclaringClass().isAssignableFrom(implementationMethod.getDeclaringClass())
                && interfaceMethod.getName().equals(implementationMethod.getName())
                && Arrays.equals(interfaceMethod.getParameterTypes(), implementationMethod.getParameterTypes());
    }

    public static Method getMethod(Class<?> base, String name, Class<?>... parameterTypes) {
        try {
            return base.getMethod(name, parameterTypes);
        } catch (NoSuchMethodException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

}

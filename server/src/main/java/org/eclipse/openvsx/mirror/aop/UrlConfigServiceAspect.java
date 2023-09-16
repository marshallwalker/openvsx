/** ******************************************************************************
 * Copyright (c) 2022 Precies. Software Ltd and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
package org.eclipse.openvsx.mirror.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.eclipse.openvsx.UrlConfigService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Aspect
@Component
@ConditionalOnProperty(value = "ovsx.data.mirror.enabled", havingValue = "true")
public class UrlConfigServiceAspect {

    @Around("execution(* org.eclipse.openvsx.UrlConfigService.getUpstreamGalleryUrl(..))")
    public Object getUpstreamGalleryUrl(ProceedingJoinPoint joinPoint) throws Throwable {
        var urlConfigService = (UrlConfigService) joinPoint.getTarget();
        return urlConfigService.getMirrorServerUrl() + "/vscode/gallery";
    }
}
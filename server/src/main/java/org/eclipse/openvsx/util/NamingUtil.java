/** ******************************************************************************
 * Copyright (c) 2023 Precies. Software Ltd and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
package org.eclipse.openvsx.util;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.openvsx.adapter.ExtensionQueryResult;
import org.eclipse.openvsx.entities.Extension;
import org.eclipse.openvsx.entities.ExtensionVersion;
import org.eclipse.openvsx.json.ExtensionJson;
import org.eclipse.openvsx.search.ExtensionSearch;

public class NamingUtil {

    private NamingUtil() {}

    public static String toFileFormat(ExtensionVersion extVersion, String suffix) {
        return toFileFormat(extVersion) + suffix;
    }

    public static String toFileFormat(ExtensionVersion extVersion) {
        var extension = extVersion.getExtension();
        var namespace = extension.getNamespace();
        return toFileFormat(namespace.getName(), extension.getName(), extVersion.getTargetPlatform(), extVersion.getVersion());
    }

    public static String toFileFormat(String namespace, String extension, String targetPlatform, String version, String suffix) {
        return toFileFormat(namespace, extension, targetPlatform, version) + suffix;
    }

    public static String toFileFormat(String namespace, String extension, String targetPlatform, String version) {
        var name = toExtensionId(namespace, extension) + "-" + version;
        if(!TargetPlatform.isUniversal(targetPlatform)) {
            name += "@" + targetPlatform;
        }

        return name;
    }

    public static String toLogFormat(ExtensionVersion extVersion) {
        var extension = extVersion.getExtension();
        var namespace = extension.getNamespace();
        return toLogFormat(namespace.getName(), extension.getName(), extVersion.getTargetPlatform(), extVersion.getVersion());
    }

    public static String toLogFormat(ExtensionJson json) {
        return toLogFormat(json.namespace, json.name, json.targetPlatform, json.version);
    }

    public static String toLogFormat(String namespace, String extension, String version) {
        return toLogFormat(namespace, extension, null, version);
    }

    public static String toLogFormat(String namespace, String extension, String targetPlatform, String version) {
        var name = toExtensionId(namespace, extension);
        if(!StringUtils.isEmpty(version)) {
            name += " " + version;
        }
        if(!StringUtils.isEmpty(targetPlatform) && !TargetPlatform.isUniversal(targetPlatform)) {
            name += " (" + targetPlatform + ")";
        }

        return name;
    }

    public static String toExtensionId(Extension extension) {
        var namespace = extension.getNamespace();
        return toExtensionId(namespace.getName(), extension.getName());
    }

    public static String toExtensionId(ExtensionQueryResult.Extension extension) {
        return toExtensionId(extension.publisher.publisherName, extension.extensionName);
    }

    public static String toExtensionId(ExtensionSearch search) {
        return toExtensionId(search.namespace, search.name);
    }

    public static String toExtensionId(String namespace, String extension) {
        return namespace + "." + extension;
    }
}

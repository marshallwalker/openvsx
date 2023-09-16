/** ******************************************************************************
 * Copyright (c) 2022 Precies. Software and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
package org.eclipse.openvsx.migration;

import org.eclipse.openvsx.ExtensionProcessor;
import org.eclipse.openvsx.util.NamingUtil;
import org.eclipse.openvsx.entities.ExtractResourcesMigrationItem;
import org.eclipse.openvsx.entities.FileResource;
import org.eclipse.openvsx.repositories.RepositoryService;
import org.eclipse.openvsx.storage.AwsStorageService;
import org.eclipse.openvsx.storage.AzureBlobStorageService;
import org.eclipse.openvsx.storage.GoogleCloudStorageService;
import org.eclipse.openvsx.storage.IStorageService;
import org.jobrunr.jobs.annotations.Job;
import org.jobrunr.jobs.context.JobRunrDashboardLogger;
import org.jobrunr.jobs.lambdas.JobRequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(value = "ovsx.data.mirror.enabled", havingValue = "false", matchIfMissing = true)
public class ExtractResourcesJobRequestHandler implements JobRequestHandler<MigrationJobRequest> {

    protected final Logger logger = new JobRunrDashboardLogger(LoggerFactory.getLogger(ExtractResourcesJobRequestHandler.class));

    @Autowired
    ExtractResourcesJobService service;

    @Autowired
    MigrationService migrations;

    @Autowired
    AwsStorageService awsStorage;

    @Override
    @Job(name = "Extract resources from published extension version", retries = 3)
    public void run(MigrationJobRequest jobRequest) throws Exception {
        var extVersion = migrations.getExtension(jobRequest.getEntityId());
        logger.info("Extracting resources for: {}", NamingUtil.toLogFormat(extVersion));

        service.deleteResources(extVersion);
        var entry = migrations.getDownload(extVersion);
        var download = entry.getKey();
        try(
                var extensionFile = migrations.getExtensionFile(entry);
                var extProcessor = new ExtensionProcessor(extensionFile)
        ) {
            extProcessor.processEachResource(download.getExtension(), (resource) -> {
                resource.setStorageType(download.getStorageType());
                migrations.uploadFileResource(resource);
                migrations.persistFileResource(resource);
            });
        }

        service.deleteWebResources(extVersion);
        var storage = getStorage(resource);
        storage.uploadFile(resource);
        resource.setContent(null);
    }

    private IStorageService getStorage(FileResource resource) {
        var storages = Map.of(
                FileResource.STORAGE_AZURE, azureStorage,
                FileResource.STORAGE_GOOGLE, googleStorage,
                FileResource.STORAGE_AWS, awsStorage
        );

        return storages.get(resource.getStorageType());
    }
}

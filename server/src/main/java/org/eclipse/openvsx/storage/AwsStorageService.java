/********************************************************************************
 * Copyright (c) 2023 Marshall Walker and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/

package org.eclipse.openvsx.storage;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ObjectMetadata;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.openvsx.entities.FileResource;
import org.eclipse.openvsx.entities.Namespace;
import org.eclipse.openvsx.util.TempFile;
import org.eclipse.openvsx.util.UrlUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AwsStorageService implements IStorageService {

    @Autowired
    FileCacheDurationConfig fileCacheDurationConfig;

    @Value("${ovsx.storage.aws.access-key-id:}")
    String accessKeyId;

    @Value("${ovsx.storage.aws.secret-access-key:}")
    String secretAccessKey;

    @Value("${ovsx.storage.aws.region:}")
    String region;

    @Value("${ovsx.storage.aws.service-endpoint:}")
    String serviceEndpoint;

    @Value("${ovsx.storage.aws.bucket:}")
    String bucket;

    @Value("${ovsx.storage.aws.path-style-access:false}")
    boolean pathStyleAccess;

    private AmazonS3 s3Client;

    protected AmazonS3 getS3Client() {
        if (s3Client == null) {
            var credentials = new BasicAWSCredentials(accessKeyId, secretAccessKey);
            var s3ClientBuilder = AmazonS3ClientBuilder.standard()
                .withPathStyleAccessEnabled(pathStyleAccess)
                .withCredentials(new AWSStaticCredentialsProvider(credentials));

            if (StringUtils.isEmpty(serviceEndpoint)) {
                s3ClientBuilder.withRegion(region);
            } else {
                s3ClientBuilder.withEndpointConfiguration(
                    new EndpointConfiguration(serviceEndpoint, region));
            }
            s3Client = s3ClientBuilder.build();
        }
        return s3Client;
    }

    protected String getObjectKey(FileResource resource) {
        var extVersion = resource.getExtension();
        var extension = extVersion.getExtension();
        var namespace = extension.getNamespace();
        var segments = new String[]{namespace.getName(), extension.getName()};
        if(!extVersion.isUniversalTargetPlatform()) {
            segments = ArrayUtils.add(segments, extVersion.getTargetPlatform());
        }

        segments = ArrayUtils.add(segments, extVersion.getVersion());
        segments = ArrayUtils.addAll(segments, resource.getName().split("/"));
        return UrlUtil.createApiUrl("", segments).substring(1); // remove first '/'
    }

    protected String getObjectKey(Namespace namespace) {
        return UrlUtil.createApiUrl("", namespace.getName(), "logo", namespace.getLogoName()).substring(1); // remove first '/'
    }

    @Override
    public boolean isEnabled() {
        return !StringUtils.isEmpty(accessKeyId);
    }

    @Override
    public void uploadFile(FileResource resource) {
        var objectKey = getObjectKey(resource);
        uploadFile(resource.getContent(), resource.getName(), objectKey);
    }

    @Override
    public void uploadFile(FileResource resource, TempFile file) {
        var objectKey = getObjectKey(resource);

        try {
            var content = Files.readAllBytes(file.getPath());
            uploadFile(content, resource.getName(), objectKey);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    protected void uploadFile(byte[] content, String resourceName, String key) {
        var client = getS3Client();

        var metadata = new ObjectMetadata();
        metadata.setContentLength(content.length);
        metadata.setContentType(StorageUtil.getFileType(resourceName).toString());

        if (resourceName.endsWith(".vsix")) {
            metadata.setContentDisposition("attachment; filename=\"" + resourceName + "\"");
        } else {
            metadata.setCacheControl(StorageUtil.getCacheControl(resourceName).getHeaderValue());
        }

        try(var stream = new ByteArrayInputStream(content)) {
            client.putObject(bucket, key, stream, metadata);
        } catch(IOException exc) {
            throw new RuntimeException(exc);
        }
    }

    protected URI getObjectLocation(String objectKey) throws RuntimeException{
        var client = getS3Client();
        var instant = LocalDateTime.now().toInstant(ZoneOffset.UTC);
        instant.plus(fileCacheDurationConfig.getCacheDuration());
        var date = Date.from(instant);

        try {
            return client.generatePresignedUrl(bucket, objectKey, date).toURI();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void removeFile(FileResource resource) {
        getS3Client().deleteObject(bucket, getObjectKey(resource));
    }

    @Override
    public URI getLocation(FileResource resource) {
        return getObjectLocation(getObjectKey(resource));
    }

    @Override
    public void uploadNamespaceLogo(Namespace namespace) {
        var objectKey = getObjectKey(namespace);
        uploadFile(namespace.getLogoBytes(), namespace.getLogoName(), objectKey);
    }

    @Override
    public void removeNamespaceLogo(Namespace namespace) {
        getS3Client().deleteObject(bucket, getObjectKey(namespace));
    }

    @Override
    public URI getNamespaceLogoLocation(Namespace namespace) {
        return getObjectLocation(getObjectKey(namespace));
    }

    @Override
    public TempFile downloadNamespaceLogo(Namespace namespace) throws IOException {
        var logoFile = new TempFile("namespace-logo", ".png");
        var object = getS3Client().getObject(bucket, getObjectKey(namespace));
        var content = object.getObjectContent().readAllBytes();
        Files.write(logoFile.getPath(), content);
        return logoFile;
    }

    @Override
    public void copyFiles(List<Pair<FileResource, FileResource>> pairs) {
        var client = getS3Client();

        for(var pair : pairs) {
            var first = getObjectKey(pair.getFirst());
            var second = getObjectKey(pair.getSecond());
            client.copyObject(bucket, first, bucket, second);
        }
    }
}

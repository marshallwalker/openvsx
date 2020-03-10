/********************************************************************************
 * Copyright (c) 2019 TypeFox and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.openvsx.repositories;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Streamable;
import org.springframework.stereotype.Component;

import org.eclipse.openvsx.entities.Extension;
import org.eclipse.openvsx.entities.ExtensionBinary;
import org.eclipse.openvsx.entities.ExtensionIcon;
import org.eclipse.openvsx.entities.ExtensionReadme;
import org.eclipse.openvsx.entities.ExtensionReview;
import org.eclipse.openvsx.entities.ExtensionVersion;
import org.eclipse.openvsx.entities.PersonalAccessToken;
import org.eclipse.openvsx.entities.Namespace;
import org.eclipse.openvsx.entities.NamespaceMembership;
import org.eclipse.openvsx.entities.UserData;

@Component
public class RepositoryService {

    @Autowired NamespaceRepository namespaceRepo;
    @Autowired ExtensionRepository extensionRepo;
    @Autowired ExtensionVersionRepository extensionVersionRepo;
    @Autowired ExtensionBinaryRepository extensionBinaryRepo;
    @Autowired ExtensionIconRepository extensionIconRepo;
    @Autowired ExtensionReadmeRepository extensionReadmeRepo;
    @Autowired ExtensionReviewRepository extensionReviewRepo;
    @Autowired UserDataRepository userDataRepo;
    @Autowired NamespaceMembershipRepository membershipRepo;
    @Autowired PersonalAccessTokenRepository tokenRepo;

    public Namespace findNamespace(String name) {
        return namespaceRepo.findByNameIgnoreCase(name);
    }

    public Extension findExtension(String name, Namespace namespace) {
        return extensionRepo.findByNameIgnoreCaseAndNamespace(name, namespace);
    }

    public Extension findExtension(String name, String namespace) {
        return extensionRepo.findByNameIgnoreCaseAndNamespaceNameIgnoreCase(name, namespace);
    }

    public Streamable<Extension> findExtensions(Namespace namespace) {
        return extensionRepo.findByNamespaceOrderByNameAsc(namespace);
    }

    public Streamable<Extension> findAllExtensions() {
        return extensionRepo.findAll();
    }

    public ExtensionVersion findVersion(String version, Extension extension) {
        return extensionVersionRepo.findByVersionAndExtension(version, extension);
    }

    public ExtensionVersion findVersion(String version, String extensionName, String namespace) {
        return extensionVersionRepo.findByVersionAndExtensionNameIgnoreCaseAndExtensionNamespaceNameIgnoreCase(version, extensionName, namespace);
    }

    public Streamable<ExtensionVersion> findVersions(Extension extension) {
        return extensionVersionRepo.findByExtension(extension);
    }

    public ExtensionBinary findBinary(ExtensionVersion extVersion) {
        return extensionBinaryRepo.findByExtension(extVersion);
    }

    public ExtensionIcon findIcon(ExtensionVersion extVersion) {
        return extensionIconRepo.findByExtension(extVersion);
    }

    public ExtensionReadme findReadme(ExtensionVersion extVersion) {
        return extensionReadmeRepo.findByExtension(extVersion);
    }

    public Streamable<ExtensionReview> findActiveReviews(Extension extension) {
        return extensionReviewRepo.findByExtensionAndActiveTrue(extension);
    }

    public Streamable<ExtensionReview> findActiveReviews(Extension extension, UserData user) {
        return extensionReviewRepo.findByExtensionAndUserAndActiveTrue(extension, user);
    }

    public long countActiveReviews(Extension extension) {
        return extensionReviewRepo.countByExtensionAndActiveTrue(extension);
    }

    public UserData findUser(String provider, String providerId) {
        return userDataRepo.findByProviderAndProviderId(provider, providerId);
    }

    public NamespaceMembership findMembership(UserData user, Namespace namespace) {
        return membershipRepo.findByUserAndNamespace(user, namespace);
    }

    public Streamable<NamespaceMembership> findMemberships(Namespace namespace, String role) {
        return membershipRepo.findByNamespaceAndRoleIgnoreCase(namespace, role);
    }

    public Streamable<PersonalAccessToken> findAccessTokens(UserData user) {
        return tokenRepo.findByUser(user);
    }

    public PersonalAccessToken findAccessToken(String value) {
        return tokenRepo.findByValue(value);
    }

    public PersonalAccessToken findAccessToken(long id) {
        return tokenRepo.findById(id);
    }

}
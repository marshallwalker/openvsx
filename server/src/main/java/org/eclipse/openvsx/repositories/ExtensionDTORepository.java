/** ******************************************************************************
 * Copyright (c) 2021 Precies. Software and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 * ****************************************************************************** */
package org.eclipse.openvsx.repositories;

import org.eclipse.openvsx.dto.ExtensionDTO;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.SelectConditionStep;
import org.jooq.impl.DSL;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.eclipse.openvsx.jooq.Tables.*;

@Component
public class ExtensionDTORepository {

    @Autowired
    DSLContext dsl;

    public List<ExtensionDTO> findAllActiveById(Collection<Long> ids) {
        return fetch(findAllActive().and(EXTENSION.ID.in(ids)));
    }

    public List<ExtensionDTO> findAllActiveByPublicId(Collection<String> publicIds) {
        return fetch(findAllActive().and(EXTENSION.PUBLIC_ID.in(publicIds)));
    }

    public ExtensionDTO findActiveByNameIgnoreCaseAndNamespaceNameIgnoreCase(String name, String namespaceName) {
        return findAllActive()
                .and(DSL.upper(EXTENSION.NAME).eq(DSL.upper(name)))
                .and(DSL.upper(NAMESPACE.NAME).eq(DSL.upper(namespaceName)))
                .fetchOneInto(ExtensionDTO.class);
    }

    public Map<Long, Integer> findAllActiveReviewCountsById(Collection<Long> ids) {
        var count = DSL.count(EXTENSION_REVIEW.ID).as("count");
        return dsl.select(EXTENSION_REVIEW.EXTENSION_ID, count)
                .from(EXTENSION_REVIEW)
                .where(EXTENSION_REVIEW.ACTIVE.eq(true))
                .and(EXTENSION_REVIEW.EXTENSION_ID.in(ids))
                .groupBy(EXTENSION_REVIEW.EXTENSION_ID)
                .fetch()
                .stream()
                .collect(Collectors.toMap(r -> r.get(EXTENSION_REVIEW.EXTENSION_ID), r -> r.get(count)));
    }

    public Map<Long, Boolean> findIsPreview(Collection<Long> ids) {
        return dsl.select(EXTENSION.ID, EXTENSION_VERSION.PREVIEW)
                .from(EXTENSION)
                .join(EXTENSION_VERSION).on(EXTENSION_VERSION.ID.eq(EXTENSION.LATEST_ID))
                .where(EXTENSION.ID.in(ids))
                .fetch()
                .stream()
                .collect(Collectors.toMap(r -> r.get(EXTENSION.ID), r -> r.get(EXTENSION_VERSION.PREVIEW)));
    }

    private SelectConditionStep<Record> findAllActive() {
        var latest = EXTENSION_VERSION.as("latest");
        return dsl.select(
                    EXTENSION.ID,
                    EXTENSION.PUBLIC_ID,
                    EXTENSION.NAME,
                    EXTENSION.AVERAGE_RATING,
                    EXTENSION.DOWNLOAD_COUNT,
                    NAMESPACE.ID,
                    NAMESPACE.PUBLIC_ID,
                    NAMESPACE.NAME,
                    latest.ID,
                    latest.VERSION,
                    latest.PREVIEW,
                    latest.PRE_RELEASE,
                    latest.TIMESTAMP,
                    latest.DISPLAY_NAME,
                    latest.DESCRIPTION,
                    latest.ENGINES,
                    latest.CATEGORIES,
                    latest.TAGS,
                    latest.EXTENSION_KIND,
                    latest.REPOSITORY,
                    latest.GALLERY_COLOR,
                    latest.GALLERY_THEME,
                    latest.DEPENDENCIES,
                    latest.BUNDLED_EXTENSIONS
                )
                .from(EXTENSION)
                .join(NAMESPACE).on(NAMESPACE.ID.eq(EXTENSION.NAMESPACE_ID))
                .join(latest).on(latest.ID.eq(EXTENSION.LATEST_ID))
                .where(EXTENSION.ACTIVE.eq(true));
    }

    private List<ExtensionDTO> fetch(SelectConditionStep<Record> query) {
        return query.fetchInto(ExtensionDTO.class);
    }
}

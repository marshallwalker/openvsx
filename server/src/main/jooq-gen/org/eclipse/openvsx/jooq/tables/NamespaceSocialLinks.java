/*
 * This file is generated by jOOQ.
 */
package org.eclipse.openvsx.jooq.tables;


import java.util.Arrays;
import java.util.List;

import org.eclipse.openvsx.jooq.Keys;
import org.eclipse.openvsx.jooq.Public;
import org.eclipse.openvsx.jooq.tables.records.NamespaceSocialLinksRecord;
import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.Name;
import org.jooq.Record;
import org.jooq.Row3;
import org.jooq.Schema;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class NamespaceSocialLinks extends TableImpl<NamespaceSocialLinksRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>public.namespace_social_links</code>
     */
    public static final NamespaceSocialLinks NAMESPACE_SOCIAL_LINKS = new NamespaceSocialLinks();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<NamespaceSocialLinksRecord> getRecordType() {
        return NamespaceSocialLinksRecord.class;
    }

    /**
     * The column <code>public.namespace_social_links.namespace_id</code>.
     */
    public final TableField<NamespaceSocialLinksRecord, Long> NAMESPACE_ID = createField(DSL.name("namespace_id"), SQLDataType.BIGINT.nullable(false), this, "");

    /**
     * The column <code>public.namespace_social_links.provider</code>.
     */
    public final TableField<NamespaceSocialLinksRecord, String> PROVIDER = createField(DSL.name("provider"), SQLDataType.VARCHAR(255).nullable(false), this, "");

    /**
     * The column <code>public.namespace_social_links.social_link</code>.
     */
    public final TableField<NamespaceSocialLinksRecord, String> SOCIAL_LINK = createField(DSL.name("social_link"), SQLDataType.VARCHAR(255).nullable(false), this, "");

    private NamespaceSocialLinks(Name alias, Table<NamespaceSocialLinksRecord> aliased) {
        this(alias, aliased, null);
    }

    private NamespaceSocialLinks(Name alias, Table<NamespaceSocialLinksRecord> aliased, Field<?>[] parameters) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table());
    }

    /**
     * Create an aliased <code>public.namespace_social_links</code> table reference
     */
    public NamespaceSocialLinks(String alias) {
        this(DSL.name(alias), NAMESPACE_SOCIAL_LINKS);
    }

    /**
     * Create an aliased <code>public.namespace_social_links</code> table reference
     */
    public NamespaceSocialLinks(Name alias) {
        this(alias, NAMESPACE_SOCIAL_LINKS);
    }

    /**
     * Create a <code>public.namespace_social_links</code> table reference
     */
    public NamespaceSocialLinks() {
        this(DSL.name("namespace_social_links"), null);
    }

    public <O extends Record> NamespaceSocialLinks(Table<O> child, ForeignKey<O, NamespaceSocialLinksRecord> key) {
        super(child, key, NAMESPACE_SOCIAL_LINKS);
    }

    @Override
    public Schema getSchema() {
        return Public.PUBLIC;
    }

    @Override
    public List<ForeignKey<NamespaceSocialLinksRecord, ?>> getReferences() {
        return Arrays.<ForeignKey<NamespaceSocialLinksRecord, ?>>asList(Keys.NAMESPACE_SOCIAL_LINKS__NAMESPACE_SOCIAL_LINKS_FKEY);
    }

    private transient Namespace _namespace;

    public Namespace namespace() {
        if (_namespace == null)
            _namespace = new Namespace(this, Keys.NAMESPACE_SOCIAL_LINKS__NAMESPACE_SOCIAL_LINKS_FKEY);

        return _namespace;
    }

    @Override
    public NamespaceSocialLinks as(String alias) {
        return new NamespaceSocialLinks(DSL.name(alias), this);
    }

    @Override
    public NamespaceSocialLinks as(Name alias) {
        return new NamespaceSocialLinks(alias, this);
    }

    /**
     * Rename this table
     */
    @Override
    public NamespaceSocialLinks rename(String name) {
        return new NamespaceSocialLinks(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public NamespaceSocialLinks rename(Name name) {
        return new NamespaceSocialLinks(name, null);
    }

    // -------------------------------------------------------------------------
    // Row3 type methods
    // -------------------------------------------------------------------------

    @Override
    public Row3<Long, String, String> fieldsRow() {
        return (Row3) super.fieldsRow();
    }
}

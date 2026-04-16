DROP VIEW IF EXISTS `cnet_security_group_scopes`;
DROP VIEW IF EXISTS `cnet_security_token_scopes`;
DROP VIEW IF EXISTS `cnet_security_token_groups_view`;

DROP TRIGGER IF EXISTS `enforce_foreign_keys_on_insert`;
DROP TRIGGER IF EXISTS `enforce_foreign_keys_on_update`;

ALTER TABLE `cnet_security_entity_scopes`
    DROP FOREIGN KEY `entity_group`,
    DROP FOREIGN KEY `entity_scope`,
    DROP FOREIGN KEY `entity_token`;

ALTER TABLE `cnet_security_token_groups`
    DROP FOREIGN KEY `token_group`,
    DROP FOREIGN KEY `group_token`;

DROP TABLE IF EXISTS `cnet_security_entity_scopes`;
DROP TABLE IF EXISTS `cnet_security_schema_history`;
DROP TABLE IF EXISTS `cnet_security_scopes`;
DROP TABLE IF EXISTS `cnet_security_tokens`;
DROP TABLE IF EXISTS `cnet_security_groups`;
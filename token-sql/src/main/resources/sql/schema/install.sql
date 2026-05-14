CREATE TABLE
    IF NOT EXISTS `cnet_security_entity_scopes` (
        `id` bigint (20) UNSIGNED NOT NULL AUTO_INCREMENT,
        `scope_id` bigint (20) UNSIGNED NOT NULL,
        `token_id` bigint (20) UNSIGNED NULL,
        `group_id` varchar(255) NULL,
        `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (`id`),
        KEY `entity_scope` (`scope_id`),
        KEY `entity_token` (`token_id`),
        KEY `entity_group` (`group_id`)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE TABLE
    IF NOT EXISTS `cnet_security_groups` (
        `id` bigint (20) UNSIGNED NOT NULL AUTO_INCREMENT,
        `name` varchar(255) NOT NULL,
        `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (`id`),
        UNIQUE `unique_name` (`name`),
        KEY `group_name` (`name`)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE TABLE
    IF NOT EXISTS `cnet_security_schema_history` (
        `id` int (11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `version` varchar(50) NOT NULL,
        `installed_on` timestamp NULL DEFAULT current_timestamp(),
        `execution_time` int (11) DEFAULT NULL,
        `success` tinyint (1) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE TABLE
    IF NOT EXISTS `cnet_security_scopes` (
        `id` bigint (20) UNSIGNED NOT NULL AUTO_INCREMENT,
        `value` varchar(255) NOT NULL,
        `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (`id`),
        UNIQUE `unique_value` (`value`)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE TABLE
    IF NOT EXISTS `cnet_security_tokens` (
        `id` bigint (20) UNSIGNED NOT NULL,
        `hash` varchar(255) NOT NULL,
        `data_container` mediumblob NOT NULL,
        `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
        `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
        PRIMARY KEY (`id`)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE TABLE
    IF NOT EXISTS `cnet_security_token_groups` (
        `token_id` bigint (20) UNSIGNED NOT NULL,
        `group_id` varchar(255) NOT NULL,
        `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (`token_id`, `group_id`)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_general_ci;

CREATE
OR REPLACE VIEW `cnet_security_group_scopes` AS
SELECT
    `cnet_security_groups`.`name` AS `group`,
    `cnet_security_scopes`.`value` AS `scope`,
    `cnet_security_groups`.`created_at` AS `created_at`,
    `cnet_security_scopes`.`created_at` AS `granted_at`
FROM
    (
        (
            `cnet_security_groups`
            join `cnet_security_entity_scopes` on (
                `cnet_security_groups`.`name` = `cnet_security_entity_scopes`.`group_id`
            )
        )
        join `cnet_security_scopes` on (
            `cnet_security_entity_scopes`.`scope_id` = `cnet_security_scopes`.`id`
        )
    );

CREATE
OR REPLACE VIEW `cnet_security_token_scopes` AS
SELECT
    `cnet_security_tokens`.`id` AS `token_id`,
    `cnet_security_scopes`.`value` AS `scope`,
    `cnet_security_tokens`.`created_at` AS `created_at`,
    `cnet_security_scopes`.`created_at` AS `granted_at`
FROM
    (
        (
            `cnet_security_tokens`
            join `cnet_security_entity_scopes` on (
                `cnet_security_tokens`.`id` = `cnet_security_entity_scopes`.`token_id`
            )
        )
        join `cnet_security_scopes` on (
            `cnet_security_entity_scopes`.`scope_id` = `cnet_security_scopes`.`id`
        )
    );

CREATE
OR REPLACE VIEW `cnet_security_token_groups_view` AS
SELECT
    `cnet_security_token_groups`.`token_id`,
    `cnet_security_groups`.`name` AS group_name,
    `cnet_security_groups`.`created_at` AS granted_at
FROM
    `cnet_security_token_groups`
    JOIN `cnet_security_groups` ON (
        `cnet_security_token_groups`.`group_id` = `cnet_security_groups`.`name`
    );

ALTER TABLE `cnet_security_entity_scopes`
    ADD CONSTRAINT `entity_group` FOREIGN KEY (`group_id`) REFERENCES `cnet_security_groups` (`name`) ON DELETE CASCADE ON UPDATE CASCADE,
    ADD CONSTRAINT `entity_scope` FOREIGN KEY (`scope_id`) REFERENCES `cnet_security_scopes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    ADD CONSTRAINT `entity_token` FOREIGN KEY (`token_id`) REFERENCES `cnet_security_tokens` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `cnet_security_token_groups`
    ADD CONSTRAINT `token_group` FOREIGN KEY (`token_id`) REFERENCES `cnet_security_tokens` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

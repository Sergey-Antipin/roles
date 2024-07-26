-- liquibase formatted sql

-- changeset antipin:1721880891224-1
CREATE SEQUENCE user_seq START WITH 100 INCREMENT BY 1;

-- changeset antipin:1721880891224-2
CREATE TABLE users
(
    id       BIGINT       NOT NULL,
    username VARCHAR(255) NOT NULL,
    email    VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (id)
);

-- changeset antipin:1721880891224-3
CREATE TABLE users_roles
(
    user_id BIGINT NOT NULL,
    role    VARCHAR(255),
    CONSTRAINT pk_users_roles PRIMARY KEY (user_id, role)
);

-- changeset antipin:1721880891224-4
ALTER TABLE users_roles
    ADD CONSTRAINT fk_users_roles_on_user FOREIGN KEY (user_id) REFERENCES users (id);

INSERT INTO users(id, username, email, password)
values (1, 'user', 'email@mail.ru', '$2a$10$uIjDQLAESGIDTRONllao3O04JvfeLvthzk9slLeyQqicp6GSCx9QW'),
       (2, 'moderator', 'moderator@mail.ru', '$2y$10$Rah5Fr4EBrD.duzivJ.d1esohmUDvDJAyE8qrOM8IeINDqKUUd/Vm'),
       (3, 'admin', 'admin@mail.ru', '$2y$10$4SLfzhAA86XzLOkqaciYlur14nXrVSluROtEZVpRgeky0i2sKaZoC');



INSERT INTO users_roles(user_id, role)
values (1, 'USER'),
       (2, 'MODERATOR'),
       (3, 'ADMIN');
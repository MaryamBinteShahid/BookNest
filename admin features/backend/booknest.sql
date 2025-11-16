CREATE TABLE users (
    user_id        VARCHAR2(36)  NOT NULL,
    name           VARCHAR2(100) NOT NULL,
    email          VARCHAR2(255) NOT NULL,
    password_hash  VARCHAR2(255) NOT NULL,
    is_verified    NUMBER(1)     DEFAULT 0,
    role           VARCHAR2(20)  DEFAULT 'user',
    created_at     TIMESTAMP(6)  DEFAULT SYSTIMESTAMP,
    updated_at     TIMESTAMP(6)  DEFAULT SYSTIMESTAMP,
    
    CONSTRAINT users_pk PRIMARY KEY (user_id),
    CONSTRAINT users_email_u UNIQUE (email),
    CONSTRAINT users_role_ck CHECK (role IN ('user', 'admin')),
    CONSTRAINT users_verified_ck CHECK (is_verified IN (0,1))
);

ALTER TABLE users ADD is_suspended NUMBER(1) DEFAULT 0 
    CONSTRAINT users_suspended_ck CHECK (is_suspended IN (0,1));



INSERT INTO users (
    user_id, name, email, password_hash, is_verified, role, is_suspended
) VALUES (
    'admin',
    'admin',
    'admin@example.com',
    '$2a$10$examplehashhere123456779',  -- replace after hashing
    1,
    'admin',
    0
);


INSERT INTO users (
    user_id, name, email, password_hash, is_verified, role, is_suspended
) VALUES (
    'user1',
    'user1',
    'min@example.com',
    '$2a$10$examplehashhere123446789',  -- replace after hashing
    1,
    'user',
    0
);


INSERT INTO users (
    user_id, name, email, password_hash, is_verified, role, is_suspended
) VALUES (
    'user2',
    'user2',
    'an@example.com',
    '$2a$10$examplehashhere133456789',  -- replace after hashing
    1,
    'user',
    0
);

INSERT INTO users (
    user_id, name, email, password_hash, is_verified, role, is_suspended
) VALUES (
    'user3',
    'user3',
    'mi@example.com',
    '$2a$10$examplehashhere133456789',  -- replace after hashing
    1,
    'user',
    0
);



CREATE TABLE books (
    book_id VARCHAR2(36) PRIMARY KEY,
    title VARCHAR2(255) NOT NULL,
    description CLOB,
    subjects CLOB,
    cover_url VARCHAR2(500),
    first_publish_year NUMBER(4),
    isbn VARCHAR2(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE reviews (
    review_id VARCHAR2(36) PRIMARY KEY,
    book_id VARCHAR2(36) NOT NULL,
    user_id VARCHAR2(36) NOT NULL,
    rating NUMBER(1) NOT NULL,
    review VARCHAR2(1000),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


INSERT INTO reviews (review_id, book_id, user_id, rating, review)
VALUES ('1a2b3c4d-0001-0000-0000-000000000001', 'book-uuid-001', 'user-uuid-001', 5, 'Amazing book! Loved it.');

INSERT INTO reviews (review_id, book_id, user_id, rating, review)
VALUES ('1a2b3c4d-0002-0000-0000-000000000002', 'book-uuid-001', 'user-uuid-002', 4, 'Very good, but a bit long.');

INSERT INTO reviews (review_id, book_id, user_id, rating, review)
VALUES ('1a2b3c4d-0003-0000-0000-000000000003', 'book-uuid-002', 'user-uuid-003', 3, 'It was okay, nothing special.');

INSERT INTO reviews (review_id, book_id, user_id, rating, review)
VALUES ('1a2b3c4d-0004-0000-0000-000000000004', 'book-uuid-003', 'user-uuid-001', 5, 'Fantastic story and characters.');

INSERT INTO reviews (review_id, book_id, user_id, rating, review)
VALUES ('1a2b3c4d-0005-0000-0000-000000000005', 'book-uuid-002', 'user-uuid-002', 2, 'Not really my type of book.');

select * from reviews;
commit;

CREATE TABLE upload_requests (
    request_id VARCHAR2(50) PRIMARY KEY,
    user_id VARCHAR2(50) NOT NULL,
    title VARCHAR2(255) NOT NULL,
    description VARCHAR2(1000),
    subjects VARCHAR2(500),
    cover_url VARCHAR2(500),
    first_publish_year NUMBER,
    isbn VARCHAR2(50),
    status VARCHAR2(20) DEFAULT 'pending',
    rejection_message VARCHAR2(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_upload_user FOREIGN KEY (user_id)
        REFERENCES users(user_id)
);

INSERT INTO upload_requests (
    request_id, user_id, title, description, subjects, cover_url,
    first_publish_year, isbn, status
) VALUES (
    'req1', 'user1', 'The Silent Forest',
    'A mystery novel about a missing traveler.',
    'Mystery, Thriller',
    'https://example.com/cover1.jpg',
    2018, '9781111111111', 'pending'
);

INSERT INTO upload_requests (
    request_id, user_id, title, description, subjects, cover_url,
    first_publish_year, isbn, status
) VALUES (
    'req2', 'user3', 'Dreams of Tomorrow',
    'A futuristic sci-fi adventure.',
    'Sci-Fi, Adventure',
    'https://example.com/cover2.jpg',
    2022, '9782222222222', 'pending'
);

INSERT INTO upload_requests (
    request_id, user_id, title, description, subjects, cover_url,
    first_publish_year, isbn, status
) VALUES (
    'req3', 'user3', 'History of Space Travel',
    'A complete timeline of human space exploration.',
    'History, Science',
    'https://example.com/cover3.jpg',
    2010, '9783333333333', 'pending'
);

INSERT INTO upload_requests (
    request_id, user_id, title, description, subjects, cover_url,
    first_publish_year, isbn, status, rejection_message
) VALUES (
    'req4', 'user1', 'Broken Entry',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    'rejected',
    'Missing required fields'
);

INSERT INTO upload_requests (
    request_id, user_id, title, description, subjects, cover_url,
    first_publish_year, isbn, status
) VALUES (
    'req5', 'user3', 'Deep Ocean Secrets',
    'A detailed exploration of underwater species and ecosystems.',
    'Science, Nature, Marine Biology',
    'https://example.com/cover5.jpg',
    2020, '9784444444444', 'pending'
);
commit;


-- 2. ON DELETE CASCADE
ALTER TABLE upload_requests
ADD CONSTRAINT fk_upload_user
FOREIGN KEY (user_id)
REFERENCES users(user_id)
ON DELETE CASCADE;


const { getConnection } = require('./database');

const { v4: uuidv4 } = require('uuid');

async function viewUploadRequests(req, res) {
    let connection;
    try {
        connection = await getConnection();

        const result = await connection.execute(
            `SELECT request_id, user_id, title, description, subjects, cover_url, 
                    first_publish_year, isbn, status, rejection_message, created_at
             FROM upload_requests
             ORDER BY 
    CASE 
        WHEN status = 'pending' THEN 1
        WHEN status = 'approved' THEN 2
        WHEN status = 'rejected' THEN 3
    END,
    created_at DESC`
        );

        const requests = result.rows.map(row => ({
            request_id: row.REQUEST_ID,
            user_id: row.USER_ID,
            title: row.TITLE,
            description: row.DESCRIPTION,
            subjects: row.SUBJECTS,
            cover_url: row.COVER_URL,
            first_publish_year: row.FIRST_PUBLISH_YEAR,
            isbn: row.ISBN,
            status: row.STATUS,
            rejection_message: row.REJECTION_MESSAGE,
            created_at: row.CREATED_AT
        }));

        res.json({ message: "Upload requests retrieved successfully", requests });

    } catch (err) {
        console.error("Error fetching upload requests:", err);
        res.status(500).json({ message: "Error fetching upload requests" });
    } finally {
        if (connection) await connection.close();
    }
}


async function approveUploadRequest(req, res) {
    let connection;
    const request_id = req.params.request_id;

    try {
        connection = await getConnection();

        // 1. Fetch request details
        const request = await connection.execute(
            `SELECT * FROM upload_requests WHERE request_id = :id`,
            [request_id]
        );

        if (request.rows.length === 0) {
            return res.status(404).json({ message: "Upload request not found" });
        }

        const r = request.rows[0];

        // 2. Insert as book
        const book_id = uuidv4();
        await connection.execute(
            `INSERT INTO books (book_id, title, description, subjects, cover_url, first_publish_year, isbn)
             VALUES (:book_id, :title, :description, :subjects, :cover_url, :year, :isbn)`,
            {
                book_id,
                title: r.TITLE,
                description: r.DESCRIPTION,
                subjects: r.SUBJECTS,
                cover_url: r.COVER_URL,
                year: r.FIRST_PUBLISH_YEAR,
                isbn: r.ISBN
            }
        );

        // 3. Mark request as approved
        await connection.execute(
            `UPDATE upload_requests SET status = 'approved' WHERE request_id = :id`,
            [request_id]
        );

        await connection.commit();

        res.json({ message: "Upload request approved successfully" });

    } catch (err) {
        console.error("Error approving request:", err);
        res.status(500).json({ message: "Error approving request" });
    } finally {
        if (connection) await connection.close();
    }
}

async function rejectUploadRequest(req, res) {
    let connection;
    const request_id = req.params.request_id;
    const { message } = req.body; // optional rejection message

    try {
        connection = await getConnection();

        const result = await connection.execute(
            `UPDATE upload_requests 
             SET status = 'rejected', rejection_message = :msg
             WHERE request_id = :id`,
            { msg: message || null, id: request_id }
        );

        if (result.rowsAffected === 0) {
            return res.status(404).json({ message: "Upload request not found" });
        }

        await connection.commit();

        res.json({ message: "Upload request rejected successfully" });

    } catch (err) {
        console.error("Error rejecting upload request:", err);
        res.status(500).json({ message: "Error rejecting upload request" });
    } finally {
        if (connection) await connection.close();
    }
}


// View all reviews
async function viewReviews(req, res) {
    let connection;

    try {
        connection = await getConnection();
        const result = await connection.execute(
            `SELECT review_id, book_id, user_id, rating, review, created_at
             FROM reviews
             ORDER BY created_at DESC`
        );

        const reviews = result.rows.map(row => ({
            review_id: row.REVIEW_ID,
            book_id: row.BOOK_ID,
            user_id: row.USER_ID,
            rating: row.RATING,
            comment: row.REVIEW,
            created_at: row.CREATED_AT
        }));

        res.json({
            message: 'Reviews retrieved successfully',
            reviews
        });
    } catch (err) {
        console.error('Error retrieving reviews:', err);
        res.status(500).json({ message: 'Error retrieving reviews' });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

// Delete a review
async function deleteReview(req, res) {
    const reviewId = req.params.reviewId;
    let connection;

    try {
        connection = await getConnection();
        const result = await connection.execute(
            'DELETE FROM reviews WHERE review_id = :reviewId',
            { reviewId },
            { autoCommit: true }
        );

        if (result.rowsAffected === 0) {
            return res.status(404).json({ message: 'Review not found' });
        }

        res.json({ message: 'Review deleted successfully' });
    } catch (err) {
        console.error('Error deleting review:', err);
        res.status(500).json({ message: 'Error deleting review' });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}



//veiw Users
async function viewUsers(req, res) {
    let connection;

    try {
        connection = await getConnection();
        const result = await connection.execute(
            `SELECT user_id, name, email, role, is_verified, created_at, updated_at, is_suspended FROM users ORDER BY created_at DESC`
        );

        res.json({
            message: 'Users retrieved successfully',
            users: result.rows
        });

    } catch (err) {
        console.error('Error retrieving users:', err);
        res.status(500).json({ message: 'Error retrieving users' });
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

// Suspend user
async function suspendUser(req, res) {
    const userId = req.params.userId;
    let conn;

    try {
        conn = await getConnection();
        const result = await conn.execute(
            `UPDATE users SET is_suspended = 1 WHERE user_id = :id`,
            [userId],
            { autoCommit: true }
        );

        if (result.rowsAffected === 0) {
            return res.status(404).json({ error: `User ${userId} not found` });
        }

        res.json({ message: `User ${userId} suspended successfully` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    } finally {
        if (conn) await conn.close();
    }
}

// Unsuspend user
async function unsuspendUser(req, res) {
    const userId = req.params.userId;
    let conn;

    try {
        conn = await getConnection();
        const result = await conn.execute(
            `UPDATE users SET is_suspended = 0 WHERE user_id = :id`,
            [userId],
            { autoCommit: true }
        );

        if (result.rowsAffected === 0) {
            return res.status(404).json({ error: `User ${userId} not found` });
        }

        res.json({ message: `User ${userId} unsuspended successfully` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    } finally {
        if (conn) await conn.close();
    }
}

// Delete user
async function deleteUser(req, res) {
    const userId = req.params.userId;
    let conn;

    try {
        conn = await getConnection();
        const result = await conn.execute(
            `DELETE FROM users WHERE user_id = :id`,
            [userId],
            { autoCommit: true }
        );

        if (result.rowsAffected === 0) {
            return res.status(404).json({ error: `User ${userId} not found` });
        }

        res.json({ message: `User ${userId} deleted successfully` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    } finally {
        if (conn) await conn.close();
    }
}


module.exports = { suspendUser, unsuspendUser, viewUsers,
     deleteUser, viewReviews,
    deleteReview, viewUploadRequests, approveUploadRequest, rejectUploadRequest };

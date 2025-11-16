const { getConnection } = require('./database');
const { v4: uuidv4 } = require('uuid');

// View all reviews
async function viewReviews(req, res) {
    let connection;

    try {
        connection = await getConnection();
        const result = await connection.execute(
            `SELECT review_id, book_id, user_id, rating, comment, created_at
             FROM reviews
             ORDER BY created_at DESC`
        );

        const reviews = result.rows.map(row => ({
            review_id: row.REVIEW_ID,
            book_id: row.BOOK_ID,
            user_id: row.USER_ID,
            rating: row.RATING,
            comment: row.COMMENT,
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

module.exports = {
    viewReviews,
    deleteReview
};

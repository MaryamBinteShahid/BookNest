const axios = require('axios');

const { getConnection } = require('./database');
const { v4: uuidv4 } = require('uuid');
const oracledb = require('oracledb');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;  
oracledb.autoCommit = true;


// View all books
async function viewBooks(req, res) {
    let connection;

    try {
        connection = await getConnection();

        const result = await connection.execute(
            `SELECT book_id, title, description, subjects, cover_url, first_publish_year, isbn
             FROM books
             ORDER BY created_at DESC`,
            [],
            { 
                outFormat: oracledb.OUT_FORMAT_OBJECT,
                fetchInfo: {
                    "DESCRIPTION": { type: oracledb.STRING },
                    "SUBJECTS": { type: oracledb.STRING }
                }
            }
        );

        // Map to clean objects
        const books = result.rows.map(row => ({
            book_id: row.BOOK_ID,
            title: row.TITLE,
            description: row.DESCRIPTION,
            subjects: row.SUBJECTS,
            cover_url: row.COVER_URL,
            first_publish_year: row.FIRST_PUBLISH_YEAR,
            isbn: row.ISBN
        }));

        res.json({
            message: 'Books retrieved successfully',
            books: books
        });

    } catch (err) {
        console.error('Error retrieving books:', err);
        res.status(500).json({ message: 'Error retrieving books' });
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


// Search books by name (from your database)
async function searchBooksByName(req, res) {
    const query = req.query.q;
    if (!query) {
        return res.status(400).json({ error: 'Query parameter "q" is required' });
    }

    let conn;

    try {
        conn = await getConnection();
        const result = await conn.execute(
            `SELECT book_id, title, description, subjects, cover_url, first_publish_year, isbn 
             FROM books 
             WHERE LOWER(title) LIKE LOWER(:query)`,
            { query: `%${query}%` },
            { 
                outFormat: oracledb.OUT_FORMAT_OBJECT,
                fetchInfo: {
                    "DESCRIPTION": { type: oracledb.STRING },
                    "SUBJECTS": { type: oracledb.STRING }
                }
            }
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'No books found' });
        }

        // Map to clean objects
        const books = result.rows.map(row => ({
            book_id: row.BOOK_ID,
            title: row.TITLE,
            description: row.DESCRIPTION,
            subjects: row.SUBJECTS,
            cover_url: row.COVER_URL,
            first_publish_year: row.FIRST_PUBLISH_YEAR,
            isbn: row.ISBN
        }));

        res.json({ books });
    } catch (err) {
        console.error('Error searching books:', err);
        res.status(500).json({ error: 'Failed to search books' });
    } finally {
        if (conn) {
            try {
                await conn.close();
            } catch (err) {
                console.error('Error closing connection:', err);
            }
        }
    }
}

// Add Book
async function addBook(req, res) {
    const { title, description, subjects, cover_url, first_publish_year, isbn } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    const bookId = uuidv4();
    const conn = await getConnection();

    try {
        await conn.execute(
            `INSERT INTO books (book_id, title, description, subjects, cover_url, first_publish_year, isbn) 
             VALUES (:bookId, :title, :description, :subjects, :cover_url, :first_publish_year, :isbn)`,
            { bookId, title, description, subjects, cover_url, first_publish_year, isbn },
            { autoCommit: true }
        );
        res.json({ message: 'Book added successfully', book_id: bookId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add book' });
    } finally {
        conn.close();
    }
}

// Edit Book
async function editBook(req, res) {
  const bookId = req.params.bookId;
  const updates = req.body;

  const conn = await getConnection();

  try {
    let updateQuery = 'UPDATE books SET ';
    const updateFields = [];
    const bindVars = { bookId };

    for (const key in updates) {
      updateFields.push(`${key} = :${key}`);
      bindVars[key] = updates[key];
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields provided to update' });
    }

    updateQuery += updateFields.join(', ') + ' WHERE book_id = :bookId';

    const result = await conn.execute(updateQuery, bindVars, { autoCommit: true });

    if (result.rowsAffected === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }

    res.json({ message: 'Book updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update book' });
  } finally {
    conn.close();
  }
}


async function deleteBook(req, res) {
  const bookId = req.params.bookId;
  const conn = await getConnection();

  try {
    // Capture the result of the execute call
    const result = await conn.execute(
      'DELETE FROM books WHERE book_id = :bookId',
      { bookId },
      { autoCommit: true }
    );

    if (result.rowsAffected === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }

    res.json({ message: 'Book deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete book' });
  } finally {
    await conn.close();
  }
}




// Controller to search books and return full details (without author info)
async function searchBooks(req, res) {
    const query = req.query.q;
    if (!query) {
        return res.status(400).json({ error: 'Query parameter "q" is required' });
    }

    try {
        // Search endpoint
        const searchResp = await axios.get(`https://openlibrary.org/search.json?q=${encodeURIComponent(query)}&limit=5`);
        const books = [];

        for (const doc of searchResp.data.docs) {
            const workId = doc.key; // e.g., /works/OLxxxxW
            const workResp = await axios.get(`https://openlibrary.org${workId}.json`);

            books.push({
                title: workResp.data.title,
                description: workResp.data.description
                    ? (typeof workResp.data.description === 'string' 
                        ? workResp.data.description 
                        : workResp.data.description.value)
                    : 'No description',
                subjects: workResp.data.subjects || [],
                covers: workResp.data.covers && workResp.data.covers.length > 0
    ? [`https://covers.openlibrary.org/b/id/${workResp.data.covers[0]}-L.jpg`]
    : [],

                first_publish_year: doc.first_publish_year || null,
                isbn: doc.isbn ? doc.isbn[0] : null,
                edition_keys: doc.edition_key || []
            });
        }

        res.json({ books });
    } catch (err) {
        console.error('Error fetching books:', err.message);
        res.status(500).json({ error: 'Failed to fetch books from Open Library' });
    }
}

module.exports = {
    searchBooks,addBook, editBook, deleteBook ,viewBooks, searchBooksByName
};

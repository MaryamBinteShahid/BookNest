const axios = require('axios')
const { supabase } = require('./database');
const { v4: uuidv4 } = require('uuid');


// ---------------------------
// Books (admin-managed)
// ---------------------------

/**
 * View all books (from your books table)
 */
async function viewBooks(req, res) {
  try {
    const { data: books, error } = await supabase
      .from('books')
      .select('book_id, title, author, description, subjects, cover_url, first_publish_year, isbn, created_at, updated_at')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase error (viewBooks):', error);
      return res.status(500).json({ message: 'Error retrieving books' });
    }

    res.json({ message: 'Books retrieved successfully', books });
  } catch (err) {
    console.error('viewBooks error:', err);
    res.status(500).json({ message: 'Error retrieving books' });
  }
}

/**
 * Search books by name (database)
 * GET /books/search?q=...
 */
async function searchBooksByName(req, res) {
  const q = req.query.q;
  if (!q) return res.status(400).json({ message: 'Query parameter "q" is required' });

  try {
    // Use ilike for case-insensitive search in Postgres
    const { data: books, error } = await supabase
      .from('books')
      .select('book_id, title, author,description, subjects, cover_url, first_publish_year, isbn')
      .ilike('title', `%${q}%`)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase error (searchBooksByName):', error);
      return res.status(500).json({ message: 'Error searching books' });
    }

    if (!books || books.length === 0) {
      return res.status(404).json({ message: 'No books found' });
    }

    res.json({ message: 'Books retrieved successfully', books });
  } catch (err) {
    console.error('searchBooksByName error:', err);
    res.status(500).json({ message: 'Error searching books' });
  }
}

/**
 * Add book
 */
async function addBook(req, res) {
  try {
    const { title,author, description, subjects, cover_url, first_publish_year, isbn } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });

    const book_id = uuidv4();
    const { data, error } = await supabase
      .from('books')
      .insert([{
        book_id,
        title,
        author,
        description: description || null,
        subjects: Array.isArray(subjects) ? subjects : (subjects ? subjects : null),
        cover_url: cover_url || null,
        first_publish_year: first_publish_year || null,
        isbn: isbn || null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select();

    if (error) {
      console.error('Supabase error (addBook):', error);
      return res.status(500).json({ error: 'Failed to add book' });
    }

    res.json({ message: 'Book added successfully', book: data[0] });
  } catch (err) {
    console.error('addBook error:', err);
    res.status(500).json({ error: 'Failed to add book' });
  }
}

/**
 * Edit book (partial updates allowed)
 */
async function editBook(req, res) {
  const bookId = req.params.bookId;
  const updates = req.body || {};

  // Don't allow changing book_id
  delete updates.book_id;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No fields provided to update' });
  }

  // Normalize subjects if provided as array/string
  if (updates.subjects && !Array.isArray(updates.subjects)) {
    updates.subjects = updates.subjects;
  }

  updates.updated_at = new Date().toISOString();

  try {
    const { data, error } = await supabase
      .from('books')
      .update(updates)
      .eq('book_id', bookId)
      .select();

    if (error) {
      console.error('Supabase error (editBook):', error);
      return res.status(500).json({ error: 'Failed to update book' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }

    res.json({ message: 'Book updated successfully', book: data[0] });
  } catch (err) {
    console.error('editBook error:', err);
    res.status(500).json({ error: 'Failed to update book' });
  }
}

/**
 * Delete book
 */
async function deleteBook(req, res) {
  const bookId = req.params.bookId;

  try {
    const { data, error } = await supabase
      .from('books')
      .delete()
      .eq('book_id', bookId)
      .select();

    if (error) {
      console.error('Supabase error (deleteBook):', error);
      return res.status(500).json({ error: 'Failed to delete book' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Book not found' });
    }

    res.json({ message: 'Book deleted successfully' });
  } catch (err) {
    console.error('deleteBook error:', err);
    res.status(500).json({ error: 'Failed to delete book' });
  }
}
// // Controller to search books and return full details (without author info)
// async function searchBooks(req, res) {
//     const query = req.query.q;
//     if (!query) {
//         return res.status(400).json({ error: 'Query parameter "q" is required' });
//     }

//     try {
//         // Search endpoint
//         const searchResp = await axios.get(`https://openlibrary.org/search.json?q=${encodeURIComponent(query)}&limit=5`);
//         const books = [];

//         for (const doc of searchResp.data.docs) {
//             const workId = doc.key; // e.g., /works/OLxxxxW
//             const workResp = await axios.get(`https://openlibrary.org${workId}.json`);

//             books.push({
//                 title: workResp.data.title,
//                 author: workResp.data.title,
//                 description: workResp.data.description
//                     ? (typeof workResp.data.description === 'string' 
//                         ? workResp.data.description 
//                         : workResp.data.description.value)
//                     : 'No description',
//                 subjects: workResp.data.subjects || [],
//                 covers: workResp.data.covers && workResp.data.covers.length > 0
//     ? [`https://covers.openlibrary.org/b/id/${workResp.data.covers[0]}-L.jpg`]
//     : [],

//                 first_publish_year: doc.first_publish_year || null,
//                 isbn: doc.isbn ? doc.isbn[0] : null,
//                 edition_keys: doc.edition_key || []
//             });
//         }

//         res.json({ books });
//     } catch (err) {
//         console.error('Error fetching books:', err.message);
//         res.status(500).json({ error: 'Failed to fetch books from Open Library' });
//     }
// }

module.exports = {
    addBook, editBook, deleteBook ,viewBooks, searchBooksByName
};
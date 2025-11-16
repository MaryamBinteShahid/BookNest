const express = require('express');
const router = express.Router();
const { searchBooks, addBook, editBook, deleteBook,viewBooks, searchBooksByName } = require('./bookController');



router.post('/', addBook);
router.put('/:bookId', editBook);
router.delete('/:bookId', deleteBook);

// GET /books/search?q=<query>
router.get('/search', searchBooks);

// View all books
router.get('/', viewBooks);
router.get('/search_local', searchBooksByName);

module.exports = router;

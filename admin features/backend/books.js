// books.js

const API_BASE = 'http://localhost:3000';

// DOM Elements
const booksTable = document.getElementById('booksTable').querySelector('tbody');
const booksCount = document.getElementById('booksCount');
const bookForm = document.getElementById('bookForm');
const bookModalTitle = document.getElementById('bookModalTitle');
const bookIdInput = document.getElementById('bookId');

const bookTitle = document.getElementById('bookTitle');
const bookAuthor = document.getElementById('bookAuthor');
const bookCategory = document.getElementById('bookCategory');
const bookCover = document.getElementById('bookCover');
const bookRating = document.getElementById('bookRating');
const bookSearch = document.getElementById('bookSearch');

// ----------------------
// Helper Functions
// ----------------------
function clearForm() {
    bookIdInput.value = '';
    bookTitle.value = '';
    bookAuthor.value = '';
    bookCategory.value = '';
    bookCover.value = '';
    bookRating.value = '';
}

// Fetch all books
async function loadBooks(query = '') {
    let url = `${API_BASE}/books`;
    if (query) url = `${API_BASE}/books/search?q=${encodeURIComponent(query)}`;

    try {
        const res = await fetch(url);
        const data = await res.json();

        const books = data.books || [];
        booksCount.textContent = books.length;

        booksTable.innerHTML = '';
        books.forEach((book, i) => {
            const tr = document.createElement('tr');

            tr.innerHTML = `
                <td>${i + 1}</td>
                <td>${book.title}</td>
                <td>${book.author || '-'}</td>
                <td>${book.subjects ? book.subjects.join(', ') : '-'}</td>
                <td>${book.rating ?? '-'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-brand me-1 editBtn">Edit</button>
                    <button class="btn btn-sm btn-outline-danger deleteBtn">Delete</button>
                </td>
            `;

            // Edit button
            tr.querySelector('.editBtn').addEventListener('click', () => {
                bookModalTitle.textContent = 'Edit Book';
                bookIdInput.value = book.book_id;
                bookTitle.value = book.title;
                bookAuthor.value = book.author || '';
                bookCategory.value = book.subjects ? book.subjects[0] : '';
                bookCover.value = book.cover_url || '';
                bookRating.value = book.rating || 0;
                const bookModal = new bootstrap.Modal(document.getElementById('bookModal'));
                bookModal.show();
            });

            // Delete button
            tr.querySelector('.deleteBtn').addEventListener('click', async () => {
                if (confirm(`Are you sure you want to delete "${book.title}"?`)) {
                    try {
                        const delRes = await fetch(`${API_BASE}/books/${book.book_id}`, {
                            method: 'DELETE'
                        });
                        const delData = await delRes.json();
                        alert(delData.message);
                        loadBooks(bookSearch.value);
                    } catch (err) {
                        console.error(err);
                        alert('Failed to delete book');
                    }
                }
            });

            booksTable.appendChild(tr);
        });

    } catch (err) {
        console.error('Error loading books:', err);
    }
}

// ----------------------
// Add/Edit Book
// ----------------------
bookForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const id = bookIdInput.value;
    const payload = {
        title: bookTitle.value,
        subjects: bookCategory.value ? [bookCategory.value] : [],
        cover_url: bookCover.value,
        rating: parseFloat(bookRating.value)
    };

    try {
        let res;
        if (id) {
            // Edit
            res = await fetch(`${API_BASE}/books/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } else {
            // Add
            res = await fetch(`${API_BASE}/books`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }

        const data = await res.json();
        alert(data.message || 'Success');

        clearForm();
        const bookModal = bootstrap.Modal.getInstance(document.getElementById('bookModal'));
        bookModal.hide();
        loadBooks(bookSearch.value);

    } catch (err) {
        console.error(err);
        alert('Failed to save book');
    }
});

// ----------------------
// Search books
// ----------------------
bookSearch.addEventListener('input', () => {
    loadBooks(bookSearch.value);
});

// ----------------------
// Initial load
// ----------------------
loadBooks();

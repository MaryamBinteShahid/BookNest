const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase Configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Google Books API Configuration
const GOOGLE_BOOKS_API_KEY = process.env.GOOGLE_BOOKS_API_KEY;
const GOOGLE_BOOKS_BASE_URL = 'https://www.googleapis.com/books/v1/volumes';

// Search endpoint - searches both Supabase and Google Books
app.get('/api/search', async (req, res) => {
  try {
    const { query, type = 'all', page = 1, limit = 10 } = req.query;

    if (!query) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    const results = await searchBooks(query, type, parseInt(page), parseInt(limit));
    
    res.json({
      success: true,
      data: results,
      total: results.length,
      page: parseInt(page),
      limit: parseInt(limit)
    });

  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to search books',
      message: error.message 
    });
  }
});

// Get book details by ID
app.get('/api/book/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { source } = req.query; // 'supabase' or 'google'

    let bookDetails;

    if (source === 'supabase') {
      bookDetails = await getSupabaseBookDetails(id);
    } else {
      bookDetails = await getGoogleBookDetails(id);
    }

    if (!bookDetails) {
      return res.status(404).json({ 
        success: false, 
        error: 'Book not found' 
      });
    }

    res.json({
      success: true,
      data: bookDetails
    });

  } catch (error) {
    console.error('Book details error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch book details',
      message: error.message 
    });
  }
});

// Search function combining both databases
async function searchBooks(query, type, page, limit) {
  const results = [];
  
  // Search Supabase first
  const supabaseResults = await searchSupabase(query, type);
  results.push(...supabaseResults);

  // Search Google Books API
  const googleResults = await searchGoogleBooks(query, type);
  results.push(...googleResults);

  // Remove duplicates based on ISBN
  const uniqueResults = removeDuplicates(results);

  // Paginate results
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  
  return uniqueResults.slice(startIndex, endIndex);
}

// Search Supabase books table
async function searchSupabase(query, type) {
  try {
    let supabaseQuery = supabase.from('books').select('*');

    // Build query based on search type
    switch (type) {
      case 'title':
        supabaseQuery = supabaseQuery.ilike('title', `%${query}%`);
        break;
      case 'author':
        supabaseQuery = supabaseQuery.ilike('author', `%${query}%`);
        break;
      case 'publisher':
        supabaseQuery = supabaseQuery.ilike('publisher', `%${query}%`);
        break;
      case 'genre':
        supabaseQuery = supabaseQuery.ilike('genre', `%${query}%`);
        break;
      default: // 'all'
        supabaseQuery = supabaseQuery.or(
          `title.ilike.%${query}%,author.ilike.%${query}%,publisher.ilike.%${query}%,genre.ilike.%${query}%`
        );
    }

    const { data, error } = await supabaseQuery.limit(50);

    if (error) throw error;

    // Format Supabase results
    return (data || []).map(book => ({
      id: book.book_id,
      title: book.title || 'Unknown Title',
      author: book.author || 'Unknown Author',
      publisher: book.publisher || 'Unknown Publisher',
      publishedDate: book.first_publish_year || book.publishing_date || 'Unknown',
      genre: book.genre || 'Unknown',
      thumbnail: book.image_url || book.thumbnail || '/placeholder-book.png',
      isbn: book.isbn || '',
      summary: book.summary || book.description || '',
      rating: book.rating || 0,
      reviews: book.reviews || [],
      source: 'supabase'
    }));

  } catch (error) {
    console.error('Supabase search error:', error);
    return [];
  }
}

// Search Google Books API
async function searchGoogleBooks(query, type) {
  try {
    let searchQuery = query;

    // Build query based on search type
    switch (type) {
      case 'title':
        searchQuery = `intitle:${query}`;
        break;
      case 'author':
        searchQuery = `inauthor:${query}`;
        break;
      case 'publisher':
        searchQuery = `inpublisher:${query}`;
        break;
      case 'genre':
        searchQuery = `subject:${query}`;
        break;
      default:
        searchQuery = query;
    }

    const response = await axios.get(GOOGLE_BOOKS_BASE_URL, {
      params: {
        q: searchQuery,
        key: GOOGLE_BOOKS_API_KEY,
        maxResults: 20,
        printType: 'books'
      }
    });

    if (!response.data.items) return [];

    // Format Google Books results
    return response.data.items.map(item => {
      const volumeInfo = item.volumeInfo;
      return {
        id: item.id,
        title: volumeInfo.title || 'Unknown Title',
        author: volumeInfo.authors ? volumeInfo.authors.join(', ') : 'Unknown Author',
        publisher: volumeInfo.publisher || 'Unknown Publisher',
        publishedDate: volumeInfo.publishedDate || 'Unknown',
        genre: volumeInfo.categories ? volumeInfo.categories.join(', ') : 'Unknown',
        thumbnail: volumeInfo.imageLinks?.thumbnail || volumeInfo.imageLinks?.smallThumbnail || '/placeholder-book.png',
        isbn: volumeInfo.industryIdentifiers?.[0]?.identifier || '',
        summary: volumeInfo.description || 'No description available',
        rating: volumeInfo.averageRating || 0,
        reviews: [],
        source: 'google'
      };
    });

  } catch (error) {
    console.error('Google Books API error:', error);
    return [];
  }
}

// Get detailed book info from Supabase
async function getSupabaseBookDetails(bookId) {
  try {
    const { data, error } = await supabase
      .from('books')
      .select('*')
      .eq('book_id', bookId)
      .single();

    if (error) throw error;
    if (!data) return null;

    return {
      id: data.book_id,
      title: data.title || 'Unknown Title',
      author: data.author || 'Unknown Author',
      publisher: data.publisher || 'Unknown Publisher',
      publishedDate: data.first_publish_year || data.publishing_date || 'Unknown',
      genre: data.genre || 'Unknown',
      image: data.image_url || data.thumbnail || '/placeholder-book.png',
      isbn: data.isbn || '',
      summary: data.summary || data.description || 'No description available',
      rating: data.rating || 0,
      reviews: data.reviews || [],
      source: 'supabase'
    };

  } catch (error) {
    console.error('Supabase book details error:', error);
    return null;
  }
}

// Get detailed book info from Google Books API
async function getGoogleBookDetails(bookId) {
  try {
    const response = await axios.get(`${GOOGLE_BOOKS_BASE_URL}/${bookId}`, {
      params: {
        key: GOOGLE_BOOKS_API_KEY
      }
    });

    const volumeInfo = response.data.volumeInfo;

    return {
      id: response.data.id,
      title: volumeInfo.title || 'Unknown Title',
      author: volumeInfo.authors ? volumeInfo.authors.join(', ') : 'Unknown Author',
      publisher: volumeInfo.publisher || 'Unknown Publisher',
      publishedDate: volumeInfo.publishedDate || 'Unknown',
      genre: volumeInfo.categories ? volumeInfo.categories.join(', ') : 'Unknown',
      image: volumeInfo.imageLinks?.large || volumeInfo.imageLinks?.medium || volumeInfo.imageLinks?.thumbnail || '/placeholder-book.png',
      isbn: volumeInfo.industryIdentifiers?.[0]?.identifier || '',
      summary: volumeInfo.description || 'No description available',
      rating: volumeInfo.averageRating || 0,
      ratingsCount: volumeInfo.ratingsCount || 0,
      pageCount: volumeInfo.pageCount || 'Unknown',
      language: volumeInfo.language || 'Unknown',
      reviews: [],
      source: 'google'
    };

  } catch (error) {
    console.error('Google Books details error:', error);
    return null;
  }
}

// Remove duplicate books based on ISBN or title similarity
function removeDuplicates(books) {
  const seen = new Map();
  const unique = [];

  for (const book of books) {
    const key = book.isbn || book.title.toLowerCase();
    
    if (!seen.has(key)) {
      seen.set(key, true);
      unique.push(book);
    } else if (book.source === 'supabase') {
      // Prefer Supabase results over Google Books if duplicate
      const index = unique.findIndex(b => (b.isbn === book.isbn || b.title.toLowerCase() === book.title.toLowerCase()));
      if (index !== -1 && unique[index].source === 'google') {
        unique[index] = book;
      }
    }
  }

  return unique;
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'BookNest API is running' });
});

app.listen(PORT, () => {
  console.log(`BookNest server running on port ${PORT}`);
});
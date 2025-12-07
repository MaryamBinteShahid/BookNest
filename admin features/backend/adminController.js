// adminController.js (Supabase version)

const { supabase } = require('../../Login_Signup/Backend/database');
const { v4: uuidv4 } = require('uuid');
/**
 * View all users
 */
async function viewUsers(req, res) {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('user_id, name, email, role, is_verified, is_suspended, created_at, updated_at')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase error (viewUsers):', error);
      return res.status(500).json({ message: 'Error retrieving users' });
    }

    res.json({
      message: 'Users retrieved successfully',
      users
    });
  } catch (err) {
    console.error('Error retrieving users:', err);
    res.status(500).json({ message: 'Error retrieving users' });
  }
}

/**
 * Suspend user
 */
async function suspendUser(req, res) {
  const userId = req.params.userId;

  try {
    const { data, error } = await supabase
      .from('users')
      .update({ is_suspended: true, updated_at: new Date().toISOString() })
      .eq('user_id', userId)
      .select();

    if (error) {
      console.error('Supabase error (suspendUser):', error);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ error: `User ${userId} not found` });
    }

    res.json({ message: `User ${userId} suspended successfully` });
  } catch (err) {
    console.error('suspendUser error:', err);
    res.status(500).json({ error: 'Database error' });
  }
}

/**
 * Unsuspend user
 */
async function unsuspendUser(req, res) {
  const userId = req.params.userId;

  try {
    const { data, error } = await supabase
      .from('users')
      .update({ is_suspended: false, updated_at: new Date().toISOString() })
      .eq('user_id', userId)
      .select();

    if (error) {
      console.error('Supabase error (unsuspendUser):', error);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ error: `User ${userId} not found` });
    }

    res.json({ message: `User ${userId} unsuspended successfully` });
  } catch (err) {
    console.error('unsuspendUser error:', err);
    res.status(500).json({ error: 'Database error' });
  }
}

/**
 * Delete user
 */
async function deleteUser(req, res) {
  const userId = req.params.userId;

  try {
    const { data, error } = await supabase
      .from('users')
      .delete()
      .eq('user_id', userId)
      .select();

    if (error) {
      console.error('Supabase error (deleteUser):', error);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ error: `User ${userId} not found` });
    }

    res.json({ message: `User ${userId} deleted successfully` });
  } catch (err) {
    console.error('deleteUser error:', err);
    res.status(500).json({ error: 'Database error' });
  }
}


// ---------------------------
// Reviews (admin)
// ---------------------------

/**
 * View all reviews
 */
async function viewReviews(req, res) {
  try {
    const { data: reviews, error } = await supabase
      .from('reviews')
      .select('review_id, book_id, user_id, rating, review, created_at')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase error (viewReviews):', error);
      return res.status(500).json({ message: 'Error retrieving reviews' });
    }

    res.json({ message: 'Reviews retrieved successfully', reviews });
  } catch (err) {
    console.error('viewReviews error:', err);
    res.status(500).json({ message: 'Error retrieving reviews' });
  }
}

/**
 * Delete a review
 */
async function deleteReview(req, res) {
  const reviewId = req.params.reviewId;

  try {
    const { data, error } = await supabase
      .from('reviews')
      .delete()
      .eq('review_id', reviewId)
      .select();

    if (error) {
      console.error('Supabase error (deleteReview):', error);
      return res.status(500).json({ message: 'Error deleting review' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: 'Review not found' });
    }

    res.json({ message: 'Review deleted successfully' });
  } catch (err) {
    console.error('deleteReview error:', err);
    res.status(500).json({ message: 'Error deleting review' });
  }
}

// ---------------------------
// Upload requests (admin review)
// ---------------------------

/**
 * View upload requests (pending first)
 */
async function viewUploadRequests(req, res) {
  try {
    const { data: requests, error } = await supabase
      .from('upload_requests')
      .select('request_id, user_id, title,author, description, subjects, cover_url, first_publish_year, isbn, status, rejection_message, created_at')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase error (viewUploadRequests):', error);
      return res.status(500).json({ message: 'Error retrieving upload requests' });
    }

    // re-order pending first on server-side (simple stable sort)
    requests.sort((a, b) => {
      const order = { pending: 1, approved: 2, rejected: 3 };
      return (order[a.status] || 4) - (order[b.status] || 4) || new Date(b.created_at) - new Date(a.created_at);
    });

    res.json({ message: 'Upload requests retrieved successfully', requests });
  } catch (err) {
    console.error('viewUploadRequests error:', err);
    res.status(500).json({ message: 'Error retrieving upload requests' });
  }
}

/**
 * Approve upload request - insert into books and mark request approved
 */
async function approveUploadRequest(req, res) {
  const requestId = req.params.request_id;

  try {
    // fetch request
    const { data: reqRows, error: reqError } = await supabase
      .from('upload_requests')
      .select('*')
      .eq('request_id', requestId)
      .single();

    if (reqError || !reqRows) {
      console.error('Supabase error (approveUploadRequest - fetch):', reqError);
      return res.status(404).json({ message: 'Upload request not found' });
    }

    // insert into books
    const bookId = uuidv4();
    const insertPayload = {
      book_id: bookId,
      title: reqRows.title,
      author: reqRows.author,
      description: reqRows.description || null,
      subjects: Array.isArray(reqRows.subjects) ? reqRows.subjects : (reqRows.subjects || null),
      cover_url: reqRows.cover_url || null,
      first_publish_year: reqRows.first_publish_year || null,
      isbn: reqRows.isbn || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const { data: bookData, error: bookError } = await supabase
      .from('books')
      .insert([insertPayload])
      .select();

    if (bookError) {
      console.error('Supabase error (approveUploadRequest - insert book):', bookError);
      return res.status(500).json({ message: 'Error adding book' });
    }

    // update request status
    const { data: updateData, error: updateError } = await supabase
      .from('upload_requests')
      .update({ status: 'approved' })
      .eq('request_id', requestId)
      .select();

    if (updateError) {
      console.error('Supabase error (approveUploadRequest - update request):', updateError);
      return res.status(500).json({ message: 'Error updating upload request' });
    }

    res.json({ message: 'Upload request approved successfully', book: bookData[0] });
  } catch (err) {
    console.error('approveUploadRequest error:', err);
    res.status(500).json({ message: 'Error approving upload request' });
  }
}

/**
 * Reject upload request
 */
async function rejectUploadRequest(req, res) {
  const requestId = req.params.request_id;
  const { message } = req.body || {};

  try {
    const { data, error } = await supabase
      .from('upload_requests')
      .update({
        status: 'rejected',
        rejection_message: message || null
      })
      .eq('request_id', requestId)
      .select();

    if (error) {
      console.error('Supabase error (rejectUploadRequest):', error);
      return res.status(500).json({ message: 'Error rejecting upload request' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ message: 'Upload request not found' });
    }

    res.json({ message: 'Upload request rejected successfully' });
  } catch (err) {
    console.error('rejectUploadRequest error:', err);
    res.status(500).json({ message: 'Error rejecting upload request' });
  }
}

module.exports = { suspendUser, unsuspendUser, viewUsers,
     deleteUser, viewReviews,
    deleteReview, viewUploadRequests, approveUploadRequest, rejectUploadRequest };


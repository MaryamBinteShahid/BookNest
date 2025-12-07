const express = require('express');
const router = express.Router();
const { suspendUser, unsuspendUser, viewUsers,deleteUser,viewReviews, deleteReview, viewUploadRequests,approveUploadRequest, rejectUploadRequest  } = require('./adminController');

router.post('/suspend/:userId', suspendUser);
router.post('/unsuspend/:userId', unsuspendUser);
router.delete('/delete/:userId', deleteUser);
router.get('/users', viewUsers);
router.get('/reviews', viewReviews);
router.delete('/reviews/:reviewId', deleteReview);
// UPLOAD REQUESTS
router.get("/upload-requests", viewUploadRequests);
router.post("/upload-requests/approve/:request_id", approveUploadRequest);
router.post("/upload-requests/reject/:request_id", rejectUploadRequest);


module.exports = router;

module.exports = router;

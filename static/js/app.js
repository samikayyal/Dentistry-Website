/**
 * JavaScript functionality for Dentistry Quiz Application
 * Phase 4 - Complete Implementation
 */

// ===========================================
// GLOBAL QUIZ STATE
// ===========================================

const quizState = {
    currentQuestion: 0,
    answers: {},
    timeRemaining: null,
    timerInterval: null,
    startTime: null,
    totalQuestions: 0
};

// ===========================================
// QUIZ TIMER FUNCTIONS
// ===========================================

/**
 * Initialize and start quiz timer
 * @param {number} duration - Duration in minutes (0 for no limit)
 * @param {number} startTime - Quiz start timestamp
 * @param {number} elapsedSeconds - Already elapsed seconds
 */
function initTimer(duration, startTime, elapsedSeconds = 0) {
    quizState.startTime = startTime || Date.now();
    const timerElement = document.getElementById('timer');
    
    if (!timerElement) return;
    
    if (duration > 0) {
        // Countdown timer
        quizState.timeRemaining = (duration * 60) - elapsedSeconds;
        
        quizState.timerInterval = setInterval(() => {
            quizState.timeRemaining--;
            
            if (quizState.timeRemaining <= 0) {
                clearInterval(quizState.timerInterval);
                autoSubmitQuiz('Time is up!');
                return;
            }
            
            updateTimerDisplay(timerElement, quizState.timeRemaining, true);
            
            // Warning at 1 minute
            if (quizState.timeRemaining === 60) {
                showNotification('warning', '⏰ One minute remaining!');
            }
        }, 1000);
    } else {
        // Elapsed timer
        let elapsed = elapsedSeconds;
        
        quizState.timerInterval = setInterval(() => {
            elapsed++;
            updateTimerDisplay(timerElement, elapsed, false);
        }, 1000);
    }
}

/**
 * Update timer display
 * @param {HTMLElement} element - Timer element
 * @param {number} seconds - Time in seconds
 * @param {boolean} isCountdown - Whether it's a countdown timer
 */
function updateTimerDisplay(element, seconds, isCountdown) {
    const minutes = Math.floor(Math.abs(seconds) / 60);
    const secs = Math.abs(seconds) % 60;
    const timeString = `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    
    element.textContent = timeString;
    
    // Color coding for countdown
    if (isCountdown) {
        if (seconds <= 60) {
            element.classList.add('text-red-500');
            element.classList.remove('text-purple-400', 'text-yellow-500');
        } else if (seconds <= 300) {
            element.classList.add('text-yellow-500');
            element.classList.remove('text-purple-400', 'text-red-500');
        }
    }
}

/**
 * Stop the quiz timer
 */
function stopTimer() {
    if (quizState.timerInterval) {
        clearInterval(quizState.timerInterval);
    }
}

// ===========================================
// QUIZ NAVIGATION FUNCTIONS
// ===========================================

/**
 * Navigate between questions
 * @param {number} direction - Direction to navigate (-1 for previous, 1 for next)
 */
function navigate(direction) {
    const questions = document.querySelectorAll('.question-block');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const submitBtn = document.getElementById('submitBtn');
    
    if (!questions.length) return;
    
    // Hide current question
    questions[quizState.currentQuestion].classList.add('hidden');
    
    // Update index
    quizState.currentQuestion += direction;
    
    // Show new question
    questions[quizState.currentQuestion].classList.remove('hidden');
    
    // Update UI
    updateQuestionUI();
    
    // Save progress
    saveQuizProgress();
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/**
 * Update question UI elements
 */
function updateQuestionUI() {
    const currentQuestionElement = document.getElementById('currentQuestion');
    const progressBar = document.getElementById('progressBar');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const submitBtn = document.getElementById('submitBtn');
    
    const totalQuestions = document.querySelectorAll('.question-block').length;
    
    if (currentQuestionElement) {
        currentQuestionElement.textContent = quizState.currentQuestion + 1;
    }
    
    if (progressBar) {
        const progress = ((quizState.currentQuestion + 1) / totalQuestions) * 100;
        progressBar.style.width = progress + '%';
    }
    
    // Button states
    if (prevBtn) {
        prevBtn.disabled = quizState.currentQuestion === 0;
    }
    
    if (quizState.currentQuestion === totalQuestions - 1) {
        if (nextBtn) nextBtn.classList.add('hidden');
        if (submitBtn) submitBtn.classList.remove('hidden');
    } else {
        if (nextBtn) nextBtn.classList.remove('hidden');
        if (submitBtn) submitBtn.classList.add('hidden');
    }
}

// ===========================================
// QUIZ SUBMISSION FUNCTIONS
// ===========================================

/**
 * Confirm quiz submission
 */
function confirmSubmit() {
    const modal = document.getElementById('confirmModal');
    const unansweredWarning = document.getElementById('unansweredWarning');
    const unansweredCount = document.getElementById('unansweredCount');
    
    const unanswered = countUnansweredQuestions();
    
    if (unanswered > 0) {
        unansweredWarning?.classList.remove('hidden');
        if (unansweredCount) {
            unansweredCount.textContent = unanswered;
        }
    } else {
        unansweredWarning?.classList.add('hidden');
    }
    
    modal?.classList.remove('hidden');
}

/**
 * Close confirmation modal
 */
function closeModal() {
    const modal = document.getElementById('confirmModal');
    modal?.classList.add('hidden');
}

/**
 * Submit the quiz
 */
function submitQuiz() {
    stopTimer();
    const form = document.getElementById('quizForm');
    if (form) {
        form.submit();
        clearQuizProgress();
    }
}

/**
 * Auto-submit quiz (e.g., when time runs out)
 * @param {string} message - Message to display
 */
function autoSubmitQuiz(message) {
    alert(message);
    submitQuiz();
}

/**
 * Count unanswered questions
 * @returns {number} - Number of unanswered questions
 */
function countUnansweredQuestions() {
    const questions = document.querySelectorAll('.question-block');
    let count = 0;
    
    questions.forEach((question) => {
        const questionIndex = question.dataset.questionIndex;
        const radios = question.querySelectorAll('input[type="radio"]');
        const answered = Array.from(radios).some(radio => radio.checked);
        
        if (!answered) {
            count++;
        }
    });
    
    return count;
}

// ===========================================
// LOCAL STORAGE FUNCTIONS
// ===========================================

/**
 * Save quiz progress to local storage
 */
function saveQuizProgress() {
    const quizId = getQuizIdFromUrl();
    if (!quizId) return;
    
    const form = document.getElementById('quizForm');
    if (!form) return;
    
    const formData = new FormData(form);
    const answers = {};
    
    for (let [key, value] of formData.entries()) {
        answers[key] = value;
    }
    
    const progress = {
        currentQuestion: quizState.currentQuestion,
        answers: answers,
        timestamp: Date.now()
    };
    
    localStorage.setItem(`quiz_${quizId}_progress`, JSON.stringify(progress));
}

/**
 * Load quiz progress from local storage
 */
function loadQuizProgress() {
    const quizId = getQuizIdFromUrl();
    if (!quizId) return;
    
    const saved = localStorage.getItem(`quiz_${quizId}_progress`);
    if (!saved) return;
    
    try {
        const progress = JSON.parse(saved);
        
        // Restore answers
        if (progress.answers) {
            for (let [key, value] of Object.entries(progress.answers)) {
                const radio = document.querySelector(`input[name="${key}"][value="${value}"]`);
                if (radio) {
                    radio.checked = true;
                }
            }
        }
        
        console.log('Quiz progress restored');
    } catch (e) {
        console.error('Error loading quiz progress:', e);
    }
}

/**
 * Clear quiz progress from local storage
 */
function clearQuizProgress() {
    const quizId = getQuizIdFromUrl();
    if (quizId) {
        localStorage.removeItem(`quiz_${quizId}_progress`);
    }
}

/**
 * Get quiz ID from URL
 * @returns {string|null} - Quiz ID or null
 */
function getQuizIdFromUrl() {
    const path = window.location.pathname;
    const match = path.match(/\/quiz\/([^\/]+)/);
    return match ? match[1] : null;
}

// ===========================================
// FORM VALIDATION
// ===========================================

/**
 * Validate form inputs
 * @param {HTMLFormElement} form - Form element
 * @returns {boolean} - True if valid
 */
function validateForm(form) {
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            isValid = false;
            input.classList.add('border-red-500');
        } else {
            input.classList.remove('border-red-500');
        }
    });
    
    return isValid;
}

/**
 * Validate email format
 * @param {string} email - Email address
 * @returns {boolean} - True if valid
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/**
 * Validate password strength
 * @param {string} password - Password
 * @returns {Object} - Validation result
 */
function validatePassword(password) {
    const result = {
        isValid: true,
        errors: []
    };
    
    if (password.length < 6) {
        result.isValid = false;
        result.errors.push('Password must be at least 6 characters long');
    }
    
    return result;
}

// ===========================================
// KEYBOARD SHORTCUTS
// ===========================================

/**
 * Initialize keyboard shortcuts
 */
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ignore if typing in input/textarea
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
            return;
        }
        
        const totalQuestions = document.querySelectorAll('.question-block').length;
        
        switch(e.key) {
            case 'ArrowRight':
            case 'n':
                e.preventDefault();
                if (quizState.currentQuestion < totalQuestions - 1) {
                    navigate(1);
                }
                break;
                
            case 'ArrowLeft':
            case 'p':
                e.preventDefault();
                if (quizState.currentQuestion > 0) {
                    navigate(-1);
                }
                break;
                
            case 'Enter':
                if (e.ctrlKey || e.metaKey) {
                    e.preventDefault();
                    if (quizState.currentQuestion === totalQuestions - 1) {
                        confirmSubmit();
                    }
                }
                break;
        }
    });
}

// ===========================================
// NOTIFICATION SYSTEM
// ===========================================

/**
 * Show notification
 * @param {string} type - Type of notification (success, error, warning, info)
 * @param {string} message - Notification message
 * @param {number} duration - Duration in milliseconds
 */
function showNotification(type, message, duration = 3000) {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg fade-in alert alert-${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, duration);
}

// ===========================================
// AJAX HELPER FUNCTIONS
// ===========================================

/**
 * Make AJAX request
 * @param {string} url - Request URL
 * @param {string} method - HTTP method
 * @param {Object} data - Request data
 * @returns {Promise} - Fetch promise
 */
async function ajaxRequest(url, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'same-origin'
    };
    
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(url, options);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('AJAX request failed:', error);
        throw error;
    }
}

// ===========================================
// UTILITY FUNCTIONS
// ===========================================

/**
 * Format time in seconds to MM:SS
 * @param {number} seconds - Time in seconds
 * @returns {string} - Formatted time
 */
function formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

/**
 * Debounce function
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ===========================================
// EVENT LISTENERS
// ===========================================

/**
 * Setup answer tracking
 */
function setupAnswerTracking() {
    const radioButtons = document.querySelectorAll('input[type="radio"]');
    
    radioButtons.forEach(radio => {
        radio.addEventListener('change', debounce(() => {
            saveQuizProgress();
        }, 500));
    });
}

/**
 * Setup form auto-save on page unload
 */
function setupAutoSave() {
    window.addEventListener('beforeunload', (e) => {
        if (document.getElementById('quizForm')) {
            saveQuizProgress();
        }
    });
}

// ===========================================
// INITIALIZATION
// ===========================================

/**
 * Initialize application
 */
function init() {
    console.log('Dentistry Quiz App Initialized');
    
    // Load saved progress
    loadQuizProgress();
    
    // Setup event listeners
    setupAnswerTracking();
    setupAutoSave();
    initKeyboardShortcuts();
    
    // Update initial UI state
    if (document.getElementById('currentQuestion')) {
        updateQuestionUI();
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', init);

// Clear progress on quiz submission
const quizForm = document.getElementById('quizForm');
if (quizForm) {
    quizForm.addEventListener('submit', () => {
        stopTimer();
        clearQuizProgress();
    });
}

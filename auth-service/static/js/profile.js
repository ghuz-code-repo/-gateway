document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initModals();
    initDocumentHandlers();
    initNotifications();
});

// Tab Management
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    // Set first tab as active by default
    if (tabButtons.length > 0) {
        tabButtons[0].classList.add('active');
        if (tabContents.length > 0) {
            tabContents[0].classList.add('active');
        }
    }

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.dataset.tab;
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            button.classList.add('active');
            const targetContent = document.getElementById(targetTab);
            if (targetContent) {
                targetContent.classList.add('active');
            }
        });
    });
}

// Modal Management
function initModals() {
    const modals = document.querySelectorAll('.modal');
    const modalTriggers = document.querySelectorAll('[data-modal]');
    const closeButtons = document.querySelectorAll('.close');

    // Open modal handlers
    modalTriggers.forEach(trigger => {
        trigger.addEventListener('click', (e) => {
            e.preventDefault();
            const modalId = trigger.dataset.modal;
            const modal = document.getElementById(modalId);
            if (modal) {
                openModal(modal);
            }
        });
    });

    // Close modal handlers
    closeButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            const modal = e.target.closest('.modal');
            if (modal) {
                closeModal(modal);
            }
        });
    });

    // Close modal on backdrop click
    modals.forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal(modal);
            }
        });
    });

    // Close modal on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const openModal = document.querySelector('.modal[style*="display: block"]');
            if (openModal) {
                closeModal(openModal);
            }
        }
    });
}

function openModal(modal) {
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    
    // Focus on first input if available
    const firstInput = modal.querySelector('input, textarea, select');
    if (firstInput) {
        setTimeout(() => firstInput.focus(), 100);
    }
}

function closeModal(modal) {
    modal.style.display = 'none';
    document.body.style.overflow = '';
    
    // Clear form if present
    const form = modal.querySelector('form');
    if (form) {
        form.reset();
    }
}

// Document Management
function initDocumentHandlers() {
    // File upload handling
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', handleFileSelect);
    });

    // Document action handlers
    document.addEventListener('click', (e) => {
        if (e.target.matches('.btn-delete-doc')) {
            handleDocumentDelete(e);
        } else if (e.target.matches('.btn-edit-doc')) {
            handleDocumentEdit(e);
        } else if (e.target.matches('.btn-download-doc')) {
            handleDocumentDownload(e);
        }
    });
}

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;

    const allowedTypes = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png'];
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
        showNotification('Неподдерживаемый формат файла. Разрешены: ' + allowedTypes.join(', '), 'error');
        e.target.value = '';
        return;
    }

    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
        showNotification('Файл слишком большой. Максимальный размер: 10MB', 'error');
        e.target.value = '';
        return;
    }

    // Show file name
    const fileNameDisplay = e.target.parentNode.querySelector('.file-name');
    if (fileNameDisplay) {
        fileNameDisplay.textContent = file.name;
        fileNameDisplay.style.display = 'block';
    }
}

function handleDocumentDelete(e) {
    e.preventDefault();
    const docId = e.target.dataset.docId;
    
    if (confirm('Вы уверены, что хотите удалить этот документ?')) {
        // Add loading state
        e.target.disabled = true;
        e.target.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        
        fetch(`/profile/documents/${docId}`, {
            method: 'DELETE',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Remove document card from DOM
                const docCard = e.target.closest('.document-card');
                if (docCard) {
                    docCard.remove();
                }
                showNotification('Документ успешно удален', 'success');
            } else {
                showNotification(data.message || 'Ошибка при удалении документа', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Ошибка при удалении документа', 'error');
        })
        .finally(() => {
            e.target.disabled = false;
            e.target.innerHTML = '<i class="fas fa-trash"></i>';
        });
    }
}

function handleDocumentEdit(e) {
    e.preventDefault();
    const docId = e.target.dataset.docId;
    const docCard = e.target.closest('.document-card');
    
    if (docCard) {
        const docName = docCard.querySelector('.document-info h4').textContent;
        const docType = docCard.querySelector('.document-info p').textContent;
        
        // Populate edit modal
        const editModal = document.getElementById('editDocumentModal');
        if (editModal) {
            const nameInput = editModal.querySelector('input[name="document_name"]');
            const typeSelect = editModal.querySelector('select[name="document_type"]');
            const docIdInput = editModal.querySelector('input[name="document_id"]');
            
            if (nameInput) nameInput.value = docName;
            if (typeSelect) typeSelect.value = docType;
            if (docIdInput) docIdInput.value = docId;
            
            openModal(editModal);
        }
    }
}

function handleDocumentDownload(e) {
    e.preventDefault();
    const docId = e.target.dataset.docId;
    
    // Add loading state
    const originalContent = e.target.innerHTML;
    e.target.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    e.target.disabled = true;
    
    window.location.href = `/profile/documents/${docId}/download`;
    
    // Reset button after a delay
    setTimeout(() => {
        e.target.innerHTML = originalContent;
        e.target.disabled = false;
    }, 2000);
}

// Notification System
function initNotifications() {
    // Auto-hide notifications after 5 seconds
    const notifications = document.querySelectorAll('.notification');
    notifications.forEach(notification => {
        setTimeout(() => {
            hideNotification(notification);
        }, 5000);
    });
}

function showNotification(message, type = 'info') {
    // Prevent duplicate notifications
    const existingNotifications = document.querySelectorAll('.notification');
    for (let existing of existingNotifications) {
        if (existing.textContent === message && existing.classList.contains(type)) {
            console.log('Duplicate notification prevented:', message);
            return;
        }
    }
    
    console.log('Showing notification:', message, type);
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Calculate position based on existing notifications
    let topPosition = 20; // Base top position
    
    existingNotifications.forEach(existing => {
        const rect = existing.getBoundingClientRect();
        topPosition = Math.max(topPosition, rect.bottom + 10 - window.pageYOffset);
    });
    
    notification.style.top = `${topPosition}px`;
    document.body.appendChild(notification);
    
    // Trigger show animation
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        hideNotification(notification);
    }, 5000);
    
    // Reposition remaining notifications when this one is removed
    notification.addEventListener('transitionend', () => {
        if (!notification.classList.contains('show')) {
            repositionNotifications();
        }
    });
}

// Make showNotification globally available
window.showNotification = showNotification;

function hideNotification(notification) {
    notification.classList.remove('show');
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
            repositionNotifications();
        }
    }, 300);
}

function repositionNotifications() {
    const notifications = document.querySelectorAll('.notification.show');
    let topPosition = 20;
    
    notifications.forEach(notification => {
        notification.style.top = `${topPosition}px`;
        const rect = notification.getBoundingClientRect();
        topPosition = rect.bottom + 10 - window.pageYOffset;
    });
}

// Make functions globally available once
if (!window.showNotification) window.showNotification = showNotification;
if (!window.hideNotification) window.hideNotification = hideNotification;
if (!window.repositionNotifications) window.repositionNotifications = repositionNotifications;

// Form validation
function validateForm(form) {
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('error');
            isValid = false;
        } else {
            field.classList.remove('error');
        }
    });
    
    return isValid;
}

// Profile form submission
document.addEventListener('submit', function(e) {
    if (e.target.matches('.profile-form')) {
        e.preventDefault();
        
        if (!validateForm(e.target)) {
            showNotification('Пожалуйста, заполните все обязательные поля', 'error');
            return;
        }
        
        const formData = new FormData(e.target);
        const submitBtn = e.target.querySelector('button[type="submit"]');
        
        // Add loading state
        const originalText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Сохранение...';
        
        fetch(e.target.action || '/profile', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Профиль успешно обновлен', 'success');
                // Update displayed information if needed
                updateProfileDisplay(data.user);
            } else {
                showNotification(data.message || 'Ошибка при сохранении профиля', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Ошибка при сохранении профиля', 'error');
        })
        .finally(() => {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        });
    }
});

function updateProfileDisplay(userData) {
    // Update profile info section with new data
    const emailDisplay = document.querySelector('.info-group .info-item[data-field="email"]');
    if (emailDisplay && userData.email) {
        emailDisplay.textContent = userData.email;
    }
    
    const phoneDisplay = document.querySelector('.info-group .info-item[data-field="phone"]');
    if (phoneDisplay && userData.phone) {
        phoneDisplay.textContent = userData.phone;
    }
    
    // Update other fields as needed
}

// Add error styling for form validation
const style = document.createElement('style');
style.textContent = `
    .form-group input.error,
    .form-group select.error,
    .form-group textarea.error {
        border-color: var(--danger-color) !important;
        box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.1) !important;
    }
    
    .file-name {
        display: none;
        margin-top: 8px;
        font-size: 14px;
        color: var(--primary-color);
        font-weight: 500;
    }
`;
document.head.appendChild(style);

// JavaScript for user form document management
// Adapted from profile.js for admin user management

// Get current user ID from current page URL
function getCurrentUserIdFromURL() {
    const path = window.location.pathname;
    const match = path.match(/\/users\/([^\/]+)/);
    return match ? match[1] : null;
}

// Function to load and display user documents for editing mode
async function loadUserDocuments() {
    const documentsGrid = document.getElementById('documentsGrid');
    if (!documentsGrid) {
        console.error('Documents grid container not found');
        return;
    }
    
    // Get user ID from URL
    const userId = getCurrentUserIdFromURL();
    if (!userId || userId === 'new') {
        // New user mode - show empty state
        documentsGrid.innerHTML = '<p class="no-documents">Документы будут доступны после создания пользователя</p>';
        return;
    }
    
    try {
        const response = await fetch(`/users/${userId}/documents`);
        if (!response.ok) {
            throw new Error(`Failed to load documents: ${response.status}`);
        }
        
        const documents = await response.json();
        
        // Clear existing documents
        documentsGrid.innerHTML = '';
        
        if (!documents || documents.length === 0) {
            documentsGrid.innerHTML = '<p class="no-documents">Документы не добавлены</p>';
            return;
        }
        
        // Create document cards with attachments
        for (const doc of documents) {
            const docCard = await createDocumentCardWithAttachments(doc, userId);
            documentsGrid.appendChild(docCard);
        }
        
    } catch (error) {
        console.error('Error loading documents:', error);
        documentsGrid.innerHTML = '<p class="error-message">Ошибка загрузки документов</p>';
    }
}

// Function to create a document card element with attachments (adapted for admin view)
async function createDocumentCardWithAttachments(doc, userId) {
    const card = document.createElement('div');
    card.className = 'document-card';
    
    // Get attachments for this document
    let attachments = [];
    let attachmentsHtml = '';
    let downloadButtonHtml = '';
    
    try {
        const response = await fetch(`/users/${userId}/documents/${doc.id}/attachments`);
        if (response.ok) {
            attachments = await response.json() || [];
            
            if (attachments.length > 0) {
                // Always create attachments display with file list initially
                const fileNames = attachments.map(att => att.filename).join(', ');
                attachmentsHtml = `
                    <div class="document-attachments">
                        <i class="fas fa-paperclip"></i>
                        <span class="attachments-list">${fileNames}</span>
                    </div>
                `;
                
                // Add download button
                downloadButtonHtml = `
                    <button type="button" class="btn btn-info btn-download-attachments" data-doc-id="${doc.id}" title="Скачать вложения" onclick="downloadDocumentAttachments('${userId}', '${doc.id}')">
                        <i class="fas fa-download"></i>
                    </button>
                `;
            } else {
                // Show message when no files are attached
                attachmentsHtml = `
                    <div class="document-attachments">
                        <span class="no-attachments">Файлы не прикреплены</span>
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error loading attachments for document:', doc.id, error);
    }
    
    // Create fields HTML
    let fieldsHtml = '';
    if (doc.fields && Object.keys(doc.fields).length > 0) {
        fieldsHtml = '<div class="document-fields">';
        for (const [key, value] of Object.entries(doc.fields)) {
            if (value) {
                // Format field names to be more readable
                const fieldName = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                fieldsHtml += `<p><strong>${fieldName}:</strong> ${value}</p>`;
            }
        }
        fieldsHtml += '</div>';
    }

    card.innerHTML = `
        <div class="document-info">
            <h4>${doc.title || doc.document_type}</h4>
            <p>Тип: ${doc.document_type}</p>
            <p>Добавлен: ${new Date(doc.created_at).toLocaleDateString('ru-RU')}</p>
        </div>
        ${fieldsHtml}
        <div class="document-bottom-row">
            ${attachmentsHtml}
            <div class="document-actions">
                ${downloadButtonHtml}
                <button type="button" class="btn btn-secondary btn-edit-doc" data-doc-id="${doc.id}" title="Редактировать документ" onclick="editDocument('${userId}', '${doc.id}')">
                    <i class="fas fa-edit"></i>
                </button>
                <button type="button" class="btn btn-danger btn-delete-doc" data-doc-id="${doc.id}" title="Удалить документ" onclick="deleteDocument('${doc.id}', '${doc.id}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `;

    // Add dynamic text switching logic for attachments
    if (attachments.length > 0) {
        const attachmentsElement = card.querySelector('.document-attachments');
        const attachmentsList = card.querySelector('.attachments-list');
        
        if (attachmentsList && attachmentsElement) {
            // Create both versions of the text
            const fileNames = attachments.map(att => att.filename).join(', ');
            const countText = `Прикреплено ${attachments.length} файлов`;
            
            // Function to check if text overflows
            const checkOverflow = () => {
                const containerWidth = attachmentsElement.offsetWidth;
                const iconWidth = 20; // Approximate width of icon + gap
                const availableWidth = containerWidth - iconWidth;
                
                // Create temporary element to measure text width
                const tempElement = document.createElement('span');
                tempElement.style.visibility = 'hidden';
                tempElement.style.position = 'absolute';
                tempElement.style.whiteSpace = 'nowrap';
                tempElement.style.fontSize = '13px';
                tempElement.textContent = fileNames;
                document.body.appendChild(tempElement);
                
                const textWidth = tempElement.offsetWidth;
                document.body.removeChild(tempElement);
                
                // Switch between list and count based on available space
                if (textWidth > availableWidth && attachments.length > 1) {
                    attachmentsList.textContent = countText;
                } else {
                    attachmentsList.textContent = fileNames;
                }
            };
            
            // Check overflow on creation and window resize
            setTimeout(checkOverflow, 0);
            window.addEventListener('resize', checkOverflow);
        }
    }
    
    // Event listeners are now handled via onclick attributes in HTML
    
    return card;
}

// Initialize document loading when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded fired!');
    
    // Only load documents if we're in edit mode and not creating a new user
    const userId = getCurrentUserIdFromURL();
    if (userId && userId !== 'new') {
        // Load documents immediately for edit mode
        loadUserDocuments();
    }
    
    // Initialize document modal handlers (if needed for future functionality)
    initDocumentModal();
    initEditDocumentModal();
    
    // Initialize service role card clicks
    initServiceRoleCardClicks();
    
    // Initialize main user form submission handler
    console.log('Calling initUserFormHandler...');
    initUserFormHandler();
});

// Initialize service role card clicks
function initServiceRoleCardClicks() {
    // Find all service role cards
    const roleCards = document.querySelectorAll('.checkbox-item.service-role');
    
    roleCards.forEach(card => {
        // Add click handler to the entire card
        card.addEventListener('click', function(e) {
            // Don't trigger if clicking directly on the checkbox or label
            if (e.target.type === 'checkbox' || e.target.tagName === 'LABEL') {
                return;
            }
            
            // Find the checkbox within this card
            const checkbox = card.querySelector('input[type="checkbox"]');
            if (checkbox) {
                // Toggle the checkbox
                checkbox.checked = !checkbox.checked;
                
                // Trigger change event to ensure any existing handlers fire
                const changeEvent = new Event('change', { bubbles: true });
                checkbox.dispatchEvent(changeEvent);
                
                console.log('Role card clicked:', checkbox.value, 'checked:', checkbox.checked);
            }
        });
        
        // Add visual feedback for hover state
        card.style.cursor = 'pointer';
    });
    
    console.log('Initialized', roleCards.length, 'service role cards for clicking');
}

// Simple modal initialization
function initDocumentModal() {
    const documentTypeSelect = document.getElementById('documentTypeSelect');
    const documentForm = document.getElementById('documentForm');
    const documentModal = document.getElementById('documentModal');
    
    if (!documentTypeSelect || !documentForm || !documentModal) {
        console.warn('Document modal elements not found');
        return;
    }
    
    // Load document types when modal is opened
    documentModal.addEventListener('modalOpened', function() {
        console.log('Document modal opened, loading document types...');
        loadDocumentTypesAdmin();
        loadAvailableServicesAdmin();
        
        // Clear and reset files area
        const newFilesArea = document.getElementById('newDocumentFilesArea');
        if (newFilesArea) {
            const filesContainer = newFilesArea.querySelector('.files-container');
            if (filesContainer) {
                filesContainer.innerHTML = '';
            }
            // Reset to disabled state
            newFilesArea.style.opacity = '0.5';
            newFilesArea.style.pointerEvents = 'none';
            newFilesArea.classList.add('disabled');
            updateUnifiedAreaVisibilityAdmin(newFilesArea);
        }
        
        // Reset document type selection
        const documentTypeSelect = document.getElementById('documentTypeSelect');
        if (documentTypeSelect) {
            documentTypeSelect.value = '';
        }
        
        // Clear document fields
        const documentFields = document.getElementById('documentFields');
        if (documentFields) {
            documentFields.innerHTML = '';
        }
        
        // Disable file input
        const fileInput = document.getElementById('documentFile');
        if (fileInput) {
            fileInput.disabled = true;
            fileInput.value = '';
        }
    });
    
    // Handle document type selection
    documentTypeSelect.addEventListener('change', handleDocumentTypeChangeAdmin);
    
    // Handle form submission
    documentForm.addEventListener('submit', handleDocumentSubmissionAdmin);
    
    // Initialize unified files area for create modal
    const newFilesArea = document.getElementById('newDocumentFilesArea');
    const fileInput = document.getElementById('documentFile');
    if (newFilesArea) {
        setupUnifiedFilesAreaAdmin(newFilesArea);
        // Initially disable files area until document type is selected
        newFilesArea.style.opacity = '0.5';
        newFilesArea.style.pointerEvents = 'none';
        newFilesArea.classList.add('disabled');
    }
    if (fileInput) {
        fileInput.disabled = true;
    }
    
    // Add document button handler
    const addDocumentBtn = document.getElementById('addDocumentBtn');
    if (addDocumentBtn) {
        addDocumentBtn.addEventListener('click', function() {
            openAddDocumentModalAdmin();
        });
    }
}

// Open add document modal
function openAddDocumentModal() {
    const modal = document.getElementById('documentModal');
    if (modal) {
        modal.style.display = 'block';
        
        // Reset form
        const form = document.getElementById('documentForm');
        if (form) {
            form.reset();
        }
    }
}

// Close document modal
function closeDocumentModal() {
    const modal = document.getElementById('documentModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Handle document form submission
async function handleDocumentSubmission(event) {
    event.preventDefault();
    
    const userId = getCurrentUserIdFromURL();
    if (!userId || userId === 'new') {
        alert('Невозможно добавить документ: пользователь не создан');
        return;
    }

    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    
    try {
        // Show loading state
        submitButton.disabled = true;
        submitButton.textContent = 'Добавление...';

        const formData = new FormData(form);
        
        // Create document data
        const documentData = {
            document_type: formData.get('documentTitle'), // Use title as type for simplicity
            title: formData.get('documentTitle'),
            fields: {}
        };

        // Send create document request
        const response = await fetch(`/users/${userId}/documents`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(documentData)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Ошибка сервера: ${response.status}`);
        }

        const result = await response.json();
        
        // If there's a file, upload it
        const fileInput = form.querySelector('#documentFile');
        if (fileInput && fileInput.files.length > 0) {
            const file = fileInput.files[0];
            const uploadFormData = new FormData();
            uploadFormData.append('file', file);

            // Get the document ID from response or use the latest document index
            const documentId = result.document_id || '0'; // Default to first document if no ID provided

            const uploadResponse = await fetch(`/users/${userId}/documents/${documentId}/attachments`, {
                method: 'POST',
                body: uploadFormData
            });

            if (!uploadResponse.ok) {
                console.warn('Document created but file upload failed');
            }
        }

        alert('Документ успешно добавлен');
        closeDocumentModal();
        loadUserDocuments(); // Reload documents list

    } catch (error) {
        console.error('Error adding document:', error);
        alert('Ошибка при добавлении документа: ' + error.message);
    } finally {
        // Restore button state
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

// Initialize edit document modal
function initEditDocumentModal() {
    const editDocumentForm = document.getElementById('editDocumentForm');
    const cancelEditBtn = document.getElementById('cancelEditDocumentBtn');
    
    if (!editDocumentForm) {
        console.log('Edit document form not found - modal may not be available');
        return;
    }
    
    // Add form submission handler
    editDocumentForm.addEventListener('submit', handleEditDocumentSubmissionAdmin);
    
    // Add cancel button handler
    if (cancelEditBtn) {
        cancelEditBtn.addEventListener('click', function() {
            closeEditDocumentModal();
        });
    }
}

// Handle edit document form submission for admin
async function handleEditDocumentSubmissionAdmin(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    
    try {
        // Show loading state
        submitButton.disabled = true;
        submitButton.textContent = 'Сохранение...';
        
        // Get document ID and user ID
        const documentId = form.querySelector('#editDocumentId').value;
        const modal = document.getElementById('editDocumentModal');
        const userId = modal.dataset.userId;
        
        if (!documentId || !userId) {
            throw new Error('ID документа или пользователя не найден');
        }
        
        // Collect form data
        const formData = {};
        const inputs = form.querySelectorAll('input[name^="field_"], textarea[name^="field_"], select[name^="field_"]');
        
        // Validate all fields first
        let hasErrors = false;
        inputs.forEach(input => {
            const fieldId = input.name.replace('field_', '');
            const value = input.value.trim();
            
            // Basic validation
            if (input.required && !value) {
                hasErrors = true;
                input.classList.add('field-error-state');
                return;
            }
            
            input.classList.remove('field-error-state');
            formData[fieldId] = value;
        });
        
        if (hasErrors) {
            throw new Error('Пожалуйста, исправьте ошибки в форме');
        }
        
        // Send update request
        const response = await fetch(`/users/${userId}/documents/${documentId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ fields: formData })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || errorData.error || `Ошибка сервера: ${response.status}`);
        }
        
        // Upload new files if any (from unified area)
        const newFiles = Array.from(document.querySelectorAll('#editDocumentFilesArea .file-item[data-status="new"]'));
        if (newFiles.length > 0) {
            const filesToUpload = newFiles.map(item => item.fileObject).filter(file => file);
            if (filesToUpload.length > 0) {
                await uploadDocumentFilesAdmin(userId, documentId, filesToUpload);
            }
        }
        
        // Success
        alert('Документ успешно обновлен');
        
        // Close modal
        closeEditDocumentModal();
        
        // Reload documents list
        setTimeout(loadUserDocuments, 100);
        
    } catch (error) {
        console.error('Error updating document:', error);
        alert(error.message || 'Ошибка при обновлении документа');
        
    } finally {
        // Restore button state
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

// Upload files to a document for admin interface
async function uploadDocumentFilesAdmin(userId, documentId, files) {
    if (!files || files.length === 0) {
        return;
    }
    
    try {
        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch(`/users/${userId}/documents/${documentId}/attachments`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                console.error(`Failed to upload ${file.name}: ${response.status}`);
                alert(`Ошибка загрузки файла ${file.name}`);
            }
        }
    } catch (error) {
        console.error('Error uploading files:', error);
        alert('Ошибка при загрузке файлов: ' + error.message);
    }
}

// Edit document function - opens modal like in profile
async function editDocument(userId, documentId) {
    try {
        // First get the document data
        const response = await fetch(`/users/${userId}/documents/${documentId}`);
        if (!response.ok) {
            throw new Error('Не удалось получить данные документа');
        }
        
        const docData = await response.json();
        docData.id = documentId; // Ensure we have the ID
        
        // Open the edit modal with the document data
        await openEditDocumentModal(docData, userId);
        
    } catch (error) {
        console.error('Error opening edit document modal:', error);
        alert('Ошибка при открытии редактора документа: ' + error.message);
    }
}

// Open edit document modal (adapted from profile.js)
async function openEditDocumentModal(docData, userId) {
    const editModal = document.getElementById('editDocumentModal');
    if (!editModal) {
        console.error('Edit document modal not found');
        return;
    }

    // Set document ID and user ID
    const docIdInput = editModal.querySelector('#editDocumentId');
    if (docIdInput) {
        docIdInput.value = docData.id;
    }
    
    // Store userId for later use
    editModal.dataset.userId = userId;

    // Load document types and set current type
    const typeSelect = editModal.querySelector('#editDocumentTypeSelect');
    if (typeSelect) {
        await loadDocumentTypesForEdit(typeSelect, docData.document_type);
        
        // Add event listener for document type change
        typeSelect.addEventListener('change', async function() {
            const fieldsContainer = editModal.querySelector('#editDocumentFields');
            if (fieldsContainer) {
                await loadDocumentFieldsForEdit(fieldsContainer, this.value, {});
            }
        });
    }

    // Load and populate fields for this document type
    const fieldsContainer = editModal.querySelector('#editDocumentFields');
    console.log('Fields container found:', !!fieldsContainer);
    console.log('Document data:', docData);
    
    if (fieldsContainer && docData.document_type) {
        console.log('Loading fields for document type:', docData.document_type, 'with data:', docData.fields);
        await loadDocumentFieldsForEdit(fieldsContainer, docData.document_type, docData.fields || {});
    } else {
        console.error('Fields container not found or document type missing:', {
            fieldsContainer: !!fieldsContainer,
            documentType: docData.document_type
        });
    }

    // Load existing attachments into unified area
    const unifiedArea = editModal.querySelector('#editDocumentFilesArea');
    console.log('Unified area found:', unifiedArea);
    if (unifiedArea) {
        // Clear previous files before loading new ones
        const filesContainer = unifiedArea.querySelector('#editFilesContainer');
        if (filesContainer) {
            const existingFiles = filesContainer.querySelectorAll('.file-item');
            existingFiles.forEach(item => item.remove());
        }
        
        console.log('Loading attachments for document:', docData.id);
        await loadDocumentAttachmentsAdmin(userId, docData.id, unifiedArea);
        setupUnifiedFilesAreaAdmin(unifiedArea);
        
        // Initialize bulk operations after files are loaded
        setupBulkActionsAdmin(editModal);
    } else {
        console.error('Unified files area not found!');
    }

    // Open the modal
    editModal.style.display = 'block';
}

// Download document attachments function
function downloadDocumentAttachments(userId, documentId) {
    // First get the list of attachments
    fetch(`/users/${userId}/documents/${documentId}/attachments`)
    .then(response => {
        if (!response.ok) {
            throw new Error('Не удалось получить список файлов');
        }
        return response.json();
    })
    .then(attachments => {
        if (!attachments || attachments.length === 0) {
            alert('У этого документа нет прикрепленных файлов');
            return;
        }

        // For each attachment, trigger download
        attachments.forEach(attachment => {
            const downloadUrl = `/users/${userId}/documents/${documentId}/attachments/${attachment.id}/download`;
            
            // Create a temporary link to trigger download
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = attachment.filename || attachment.file_name || 'document';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    })
    .catch(error => {
        console.error('Error downloading attachments:', error);
        alert('Ошибка при скачивании файлов: ' + error.message);
    });
}

// Add event listener for modal close
document.addEventListener('DOMContentLoaded', function() {
    // Close modal when clicking outside of it
    window.onclick = function(event) {
        const modal = document.getElementById('documentModal');
        const editModal = document.getElementById('editDocumentModal');
        if (event.target === modal) {
            closeDocumentModal();
        }
        if (event.target === editModal) {
            closeEditDocumentModal();
        }
    }
});

// Load document types for edit modal
async function loadDocumentTypesForEdit(selectElement, currentType) {
    try {
        const response = await fetch('/document-types');
        const documentTypes = await response.json();
        
        selectElement.innerHTML = '<option value="">Выберите тип документа</option>';
        
        documentTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type.id || type.name;
            option.textContent = type.name;
            if (type.id === currentType || type.name === currentType) {
                option.selected = true;
            }
            selectElement.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading document types:', error);
        selectElement.innerHTML = '<option value="">Ошибка загрузки типов документов</option>';
    }
}

// Load document fields for edit modal
async function loadDocumentFieldsForEdit(container, documentType, fieldValues = {}) {
    try {
        // Find the document type data
        const response = await fetch('/document-types');
        if (!response.ok) {
            throw new Error(`Failed to load document types: ${response.status}`);
        }
        
        const documentTypes = await response.json();
        const typeData = documentTypes.find(type => type.id === documentType);
        
        if (!typeData || !typeData.fields) {
            container.innerHTML = '<p>Поля для данного типа документа не найдены</p>';
            return;
        }
        
        // Clear existing fields
        container.innerHTML = '';
        
        typeData.fields.forEach(field => {
            const fieldDiv = document.createElement('div');
            fieldDiv.className = 'form-group';
            
            const label = document.createElement('label');
            label.textContent = field.label;
            label.setAttribute('for', `field_${field.id}`);
            if (field.required) {
                label.classList.add('required');
            }
            
            let input;
            switch (field.type) {
                case 'textarea':
                    input = document.createElement('textarea');
                    input.rows = 3;
                    break;
                case 'select':
                    input = document.createElement('select');
                    if (field.options) {
                        field.options.forEach(option => {
                            const optionElement = document.createElement('option');
                            optionElement.value = option.value || option;
                            optionElement.textContent = option.label || option;
                            input.appendChild(optionElement);
                        });
                    }
                    break;
                default:
                    input = document.createElement('input');
                    input.type = field.type || 'text';
            }
            
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            input.value = fieldValues[field.id] || '';
            if (field.required) {
                input.required = true;
            }
            if (field.placeholder) {
                input.placeholder = field.placeholder;
            }
            
            fieldDiv.appendChild(label);
            fieldDiv.appendChild(input);
            container.appendChild(fieldDiv);
        });
    } catch (error) {
        console.error('Error loading document fields:', error);
        container.innerHTML = '<p class="error-message">Ошибка загрузки полей документа</p>';
    }
}

// Load document attachments for admin interface
async function loadDocumentAttachmentsAdmin(userId, documentId, unifiedArea) {
    try {
        console.log('Loading attachments for user:', userId, 'document:', documentId);
        const response = await fetch(`/users/${userId}/documents/${documentId}/attachments`);
        console.log('Attachments response status:', response.status);
        
        if (!response.ok) {
            console.log('No attachments found or error loading attachments, response:', response.status);
            return;
        }
        
        const attachments = await response.json();
        console.log('Loaded attachments:', attachments);
        console.log('Attachments count:', attachments.length);
        
        // Update unified files area with existing attachments
        if (attachments && attachments.length > 0) {
            updateUnifiedFilesAreaAdmin(unifiedArea, attachments, 'uploaded');
        } else {
            console.log('No attachments to display');
        }
        
    } catch (error) {
        console.error('Error loading attachments:', error);
    }
}

// Setup unified files area for admin interface
function setupUnifiedFilesAreaAdmin(areaContainer) {
    // Determine the correct file input based on the area container
    let fileInputSelector;
    if (areaContainer.id === 'editDocumentFilesArea') {
        fileInputSelector = '#editDocumentFiles';
    } else if (areaContainer.id === 'newDocumentFilesArea') {
        fileInputSelector = '#documentFile';
    } else {
        console.error('Unknown files area container:', areaContainer.id);
        return;
    }
    
    // Add file input event listener
    const fileInput = areaContainer.parentElement.querySelector(fileInputSelector);
    console.log('Setting up file input:', fileInputSelector, fileInput);
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            console.log('File input changed:', e.target.files);
            handleUnifiedFilesChangeAdmin(e.target.files, areaContainer);
        });
    } else {
        console.error('File input not found:', fileInputSelector);
    }
    
    // Add drag and drop functionality
    areaContainer.addEventListener('dragover', function(e) {
        e.preventDefault();
        areaContainer.classList.add('drag-over');
    });
    
    areaContainer.addEventListener('dragleave', function(e) {
        e.preventDefault();
        areaContainer.classList.remove('drag-over');
    });
    
    areaContainer.addEventListener('drop', function(e) {
        e.preventDefault();
        areaContainer.classList.remove('drag-over');
        handleUnifiedFilesChangeAdmin(e.dataTransfer.files, areaContainer);
    });
    
    // Add click to area to open file dialog
    const emptyState = areaContainer.querySelector('.empty-files-state');
    if (emptyState) {
        emptyState.addEventListener('click', function() {
            console.log('Empty state clicked');
            
            // Determine the correct file input based on the area container
            let fileInputSelector;
            if (areaContainer.id === 'editDocumentFilesArea') {
                fileInputSelector = '#editDocumentFiles';
            } else if (areaContainer.id === 'newDocumentFilesArea') {
                fileInputSelector = '#documentFile';
            }
            
            const fileInput = areaContainer.parentElement.querySelector(fileInputSelector);
            if (fileInput) {
                console.log('Triggering file input click from empty state');
                fileInput.click();
            }
        });
        emptyState.style.cursor = 'pointer';
    }
}

// Handle file changes in unified area for admin
function handleUnifiedFilesChangeAdmin(files, areaContainer) {
    console.log('Files selected:', files);
    
    // Convert FileList to Array and add to existing files
    const newFiles = Array.from(files);
    
    // Get existing files
    const existingFiles = areaContainer.querySelectorAll('.file-item[data-status="new"]');
    const existingFileObjects = Array.from(existingFiles).map(item => item.fileObject).filter(f => f);
    
    // Combine with new files
    const allFiles = [...existingFileObjects, ...newFiles];
    
    // Update the unified area
    updateUnifiedFilesAreaAdmin(areaContainer, allFiles, 'new');
}

// Update unified files area for admin interface
function updateUnifiedFilesAreaAdmin(areaContainer, files, status) {
    const filesContainer = areaContainer.querySelector('#editFilesContainer');
    if (!filesContainer) return;
    
    // Clear existing files of this status to prevent duplication
    const existingFiles = filesContainer.querySelectorAll(`.file-item[data-status="${status}"]`);
    existingFiles.forEach(item => item.remove());
    
    // Add files
    files.forEach((file, index) => {
        const fileItem = createUnifiedFileItemAdmin(file, index, status);
        if (fileItem) {
            // Store file object for new files
            if (status === 'new') {
                fileItem.fileObject = file;
            }
            filesContainer.appendChild(fileItem);
        }
    });
    
    // Add "+" button if not exists
    let addButton = filesContainer.querySelector('.add-file-button');
    if (!addButton) {
        addButton = createAddFileButtonAdmin(areaContainer);
        filesContainer.appendChild(addButton);
    }
    
    // Update empty state visibility
    const emptyState = areaContainer.querySelector('#editEmptyState');
    const hasFiles = filesContainer.querySelectorAll('.file-item').length > 0;
    if (emptyState) {
        emptyState.style.display = hasFiles ? 'none' : 'flex';
    }
    
    // Update bulk actions state after files are loaded
    setTimeout(() => {
        updateBulkActionsStateAdmin();
    }, 100);
    filesContainer.style.display = hasFiles ? 'flex' : 'none';
}

// Create unified file item for admin interface
function createUnifiedFileItemAdmin(fileData, index, status) {
    console.log('Creating file item:', { fileData, index, status });
    
    const div = document.createElement('div');
    div.className = 'file-item';
    div.dataset.fileId = fileData.id || fileData.name || index;
    div.dataset.status = status;
    div.dataset.fileIndex = index;
    
    // Store file object for new files
    if (status === 'new' && fileData instanceof File) {
        div.fileObject = fileData;
    }
    
    const fileName = fileData.filename || fileData.file_name || fileData.name || 'Unknown file';
    const fileSize = fileData.filesize || fileData.size || 0;
    
    console.log('File details:', { fileName, fileSize, status });
    
    const isImage = /\.(jpg|jpeg|png|gif)$/i.test(fileName);
    const isPdf = /\.pdf$/i.test(fileName);
    
    let previewContent = '';
    if (isImage && status === 'uploaded') {
        // For uploaded files, we need to construct the preview URL
        const modal = document.getElementById('editDocumentModal');
        const userId = modal ? modal.dataset.userId : '';
        const docId = document.getElementById('editDocumentId') ? document.getElementById('editDocumentId').value : '';
        const previewUrl = `/profile/documents/${docId}/attachments/${fileData.id}/preview`;
        console.log('Creating preview for uploaded image:', {
            fileName,
            userId,
            docId,
            attachmentId: fileData.id,
            previewUrl
        });
        previewContent = `<img src="${previewUrl}" alt="${fileName}" 
                               onload="console.log('Image loaded successfully:', '${previewUrl}')"
                               onerror="console.log('Image failed to load:', '${previewUrl}'); this.style.display='none'; this.nextElementSibling.style.display='block';">
                         <i class="fas fa-file-image" style="display: none; color: #28a745;"></i>`;
    } else if (isImage && status === 'new') {
        // For new files, we'll set the src via FileReader
        previewContent = `<img class="preview-placeholder" alt="${fileName}">`;
    } else if (isPdf) {
        previewContent = `<i class="fas fa-file-pdf" style="color: #dc3545;"></i>`;
    } else {
        previewContent = `<i class="fas fa-file"></i>`;
    }
    
    const statusIcon = status === 'uploaded' ? 'fa-save' : 'fa-plus';
    const statusTitle = status === 'uploaded' ? 'Загружен' : 'Новый файл';
    
    // Get current modal data for userId and docId
    const modal = document.getElementById('editDocumentModal');
    const userId = modal ? modal.dataset.userId : '';
    const docId = document.getElementById('editDocumentId') ? document.getElementById('editDocumentId').value : '';
    
    // Generate preview button HTML if needed
    const canPreview = (status === 'uploaded' && docId && userId) || (status === 'new');
    
    // For new files, create a simplified data structure for the button
    let buttonFileData;
    if (status === 'new' && fileData instanceof File) {
        buttonFileData = {
            name: fileData.name,
            size: fileData.size,
            type: fileData.type,
            lastModified: fileData.lastModified,
            index: index
        };
    } else {
        buttonFileData = fileData;
    }
    
    const previewButtonHTML = canPreview && (isImage || isPdf) ? `
        <div class="file-preview-button">
            <button type="button" class="btn-preview-file" 
                    data-user-id="${userId}" 
                    data-doc-id="${docId}" 
                    data-file-data="${encodeURIComponent(JSON.stringify(buttonFileData))}" 
                    data-status="${status}" 
                    onclick="previewAttachmentFromButtonAdmin(this, event)" 
                    title="Предпросмотр">
                <i class="fas fa-eye"></i>
                <span>Предпросмотр</span>
            </button>
        </div>
    ` : '';

    div.innerHTML = `
        <div class="file-item-checkbox">
            <input type="checkbox" class="file-checkbox" data-file-index="${index}" data-status="${status}">
        </div>
        <div class="file-item-preview">
            ${previewContent}
        </div>
        <div class="file-item-info">
            ${fileName}
            ${previewButtonHTML}
        </div>
        <div class="file-item-status ${status}" title="${statusTitle}">
            <i class="fas ${statusIcon}"></i>
        </div>
        <div class="file-item-actions">
            <button type="button" class="file-item-action file-delete-btn" onclick="removeFileFromUnifiedAdmin(this)" title="Удалить">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;
    
    // Add click event for checkbox toggle (click on image/preview area)
    const previewElement = div.querySelector('.file-item-preview');
    if (previewElement) {
        previewElement.addEventListener('click', (e) => {
            e.stopPropagation();
            const checkbox = div.querySelector('.file-checkbox');
            if (checkbox) {
                checkbox.checked = !checkbox.checked;
                // Trigger change event to update bulk actions state
                checkbox.dispatchEvent(new Event('change'));
            }
        });
        // Add cursor pointer to indicate clickable
        previewElement.style.cursor = 'pointer';
    }
    if (isImage && status === 'new' && fileData instanceof File) {
        const img = div.querySelector('.preview-placeholder');
        if (img) {
            const reader = new FileReader();
            reader.onload = function(e) {
                img.src = e.target.result;
            };
            reader.readAsDataURL(fileData);
        }
    }
    
    // Add event listener for checkbox changes
    const checkbox = div.querySelector('.file-checkbox');
    if (checkbox) {
        checkbox.addEventListener('change', function() {
            // Toggle selected class based on checkbox state
            if (this.checked) {
                div.classList.add('selected');
            } else {
                div.classList.remove('selected');
            }
            updateBulkActionsStateAdmin();
        });
    }
    
    return div;
}

// Create add file button for admin interface
function createAddFileButtonAdmin(areaContainer) {
    const button = document.createElement('div');
    button.className = 'add-file-button';
    button.innerHTML = '<i class="fas fa-plus"></i>';
    
    button.addEventListener('click', function() {
        console.log('Add file button clicked');
        const fileInput = areaContainer.parentElement.querySelector('#editDocumentFiles');
        console.log('File input found:', fileInput);
        if (fileInput) {
            console.log('Triggering file input click');
            fileInput.click();
        } else {
            console.error('File input not found when + button clicked');
        }
    });
    
    return button;
}

// Remove file from unified area (admin)
function removeFileFromUnifiedAdmin(button) {
    const fileItem = button.closest('.file-item');
    if (fileItem) {
        fileItem.remove();
        
        // Update empty state
        const areaContainer = button.closest('.unified-files-area');
        const filesContainer = areaContainer.querySelector('#editFilesContainer');
        const emptyState = areaContainer.querySelector('#editEmptyState');
        const hasFiles = filesContainer.querySelectorAll('.file-item').length > 0;
        
        if (emptyState) {
            emptyState.style.display = hasFiles ? 'none' : 'flex';
        }
        filesContainer.style.display = hasFiles ? 'flex' : 'none';
    }
}

// Format file size helper
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Global function to close edit modal
function closeEditDocumentModal() {
    const modal = document.getElementById('editDocumentModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Delete document function
function deleteDocument(documentId, docIndex) {
    const userId = getCurrentUserIdFromURL();
    if (!userId || userId === 'new') {
        alert('Не удается определить пользователя для удаления документа');
        return;
    }

    // Confirm deletion
    if (!confirm('Вы уверены, что хотите удалить этот документ? Это действие нельзя отменить.')) {
        return;
    }

    // Use docIndex instead of documentId for deletion API
    fetch(`/users/${userId}/documents/${docIndex}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => Promise.reject(err));
        }
        return response.json();
    })
    .then(data => {
        alert('Документ успешно удален');
        // Reload documents to reflect changes
        loadUserDocuments();
    })
    .catch(error => {
        console.error('Error deleting document:', error);
        alert('Ошибка при удалении документа: ' + (error.error || 'Неизвестная ошибка'));
    });
}

// Image preview functions for admin interface
function showImagePreview(src, filename, onClose) {
    const modal = document.createElement('div');
    modal.className = 'modal file-preview-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>${filename}</h3>
                <span class="close">&times;</span>
            </div>
            <div class="modal-body">
                <img src="${src}" alt="${filename}">
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    
    // Close modal function
    const closeModal = () => {
        document.body.removeChild(modal);
        if (onClose) onClose();
    };
    
    // Close modal events
    modal.querySelector('.close').addEventListener('click', closeModal);
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
}

function showPdfPreview(src, filename, onClose) {
    const modal = document.createElement('div');
    modal.className = 'modal file-preview-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>${filename}</h3>
                <span class="close">&times;</span>
            </div>
            <div class="modal-body">
                <embed src="${src}" type="application/pdf" width="100%" height="500px">
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    
    // Close modal function
    const closeModal = () => {
        document.body.removeChild(modal);
        if (onClose) onClose();
    };
    
    // Close modal events
    modal.querySelector('.close').addEventListener('click', closeModal);
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
}

function previewAttachmentFromButtonAdmin(button, event) {
    console.log('Preview button clicked:', button);
    // Prevent form submission
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    const userId = button.dataset.userId;
    const docId = button.dataset.docId;
    const fileDataEncoded = button.dataset.fileData;
    const status = button.dataset.status;
    
    console.log('Preview data:', { userId, docId, fileDataEncoded, status });
    
    try {
        const fileData = JSON.parse(decodeURIComponent(fileDataEncoded));
        console.log('Parsed file data:', fileData);
        
        if (status === 'uploaded') {
            // For uploaded files, use server preview
            console.log('Calling previewAttachmentAdmin for uploaded file');
            previewAttachmentAdmin(userId, docId, fileData);
        } else if (status === 'new') {
            // For new files, use local preview
            console.log('Calling previewNewFileAdmin for new file');
            previewNewFileAdmin(fileData);
        }
    } catch (error) {
        console.error('Error parsing file data for preview:', error);
        alert('Ошибка открытия предпросмотра');
    }
}

function previewAttachmentAdmin(userId, docId, attachment) {
    console.log('previewAttachmentAdmin called with:', { userId, docId, attachment });
    
    const filename = attachment.filename || attachment.file_name || attachment.name || 'unknown';
    console.log('Using filename:', filename);
    
    const isImage = /\.(jpg|jpeg|png|gif)$/i.test(filename);
    const isPdf = /\.pdf$/i.test(filename);
    
    console.log('File type detection:', { isImage, isPdf });
    
    if (isImage) {
        const previewUrl = `/profile/documents/${docId}/attachments/${attachment.id}/preview`;
        console.log('Opening image preview with URL:', previewUrl);
        showImagePreview(previewUrl, filename);
    } else if (isPdf) {
        const previewUrl = `/profile/documents/${docId}/attachments/${attachment.id}/preview`;
        console.log('Opening PDF preview with URL:', previewUrl);
        showPdfPreview(previewUrl, filename);
    } else {
        console.log('File type not supported for preview, downloading instead');
        // For other file types, just download
        downloadAttachmentAdmin(userId, docId, attachment.id);
    }
}

function previewNewFileAdmin(fileData) {
    console.log('Preview new file data:', fileData);
    
    // For new files, we need to access the actual File object
    const searchId = fileData.name; // For new files, always use name as identifier
    console.log('Searching for element with data-file-id:', searchId);
    
    // Find file item by name (since new files use name as file-id)
    const fileItem = document.querySelector(`.file-item[data-file-index="${fileData.index}"][data-status="new"]`);
    console.log('Found file item:', fileItem);
    
    const fileObject = fileItem ? fileItem.fileObject : null;
    console.log('File object:', fileObject);
    
    if (!fileObject) {
        console.log('Available file items:', document.querySelectorAll('.file-item[data-status="new"]'));
        console.log('Searching for file with name:', searchId);
        
        // Try to find by all available new file items and match by name
        const allNewItems = document.querySelectorAll('.file-item[data-status="new"]');
        let foundItem = null;
        allNewItems.forEach(item => {
            console.log('Checking item with data-file-index:', item.dataset.fileIndex, 'fileObject:', item.fileObject);
            if (item.fileObject && item.fileObject.name === searchId) {
                foundItem = item;
            }
        });
        
        if (foundItem && foundItem.fileObject) {
            console.log('Found file via manual search:', foundItem.fileObject);
            previewFileObjectAdmin(foundItem.fileObject);
        } else {
            alert('Файл недоступен для предпросмотра');
        }
        return;
    }
    
    previewFileObjectAdmin(fileObject);
}

function previewFileObjectAdmin(fileObject) {
    const isImage = fileObject.type.startsWith('image/');
    const isPdf = fileObject.type === 'application/pdf';
    
    if (isImage) {
        // Create object URL for image preview
        const objectUrl = URL.createObjectURL(fileObject);
        showImagePreview(objectUrl, fileObject.name, () => {
            URL.revokeObjectURL(objectUrl);
        });
    } else if (isPdf) {
        // Create object URL for PDF preview
        const objectUrl = URL.createObjectURL(fileObject);
        showPdfPreview(objectUrl, fileObject.name, () => {
            URL.revokeObjectURL(objectUrl);
        });
    } else {
        // For other file types, create download
        const objectUrl = URL.createObjectURL(fileObject);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = fileObject.name;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
        alert('Файл скачан');
    }
}

function downloadAttachmentAdmin(userId, docId, attachmentId) {
    const link = document.createElement('a');
    link.href = `/users/${userId}/documents/${docId}/attachments/${attachmentId}/download`;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Bulk operations for file management
function updateBulkActionsStateAdmin() {
    const checkboxes = document.querySelectorAll('#editDocumentFilesArea .file-checkbox');
    const checkedBoxes = document.querySelectorAll('#editDocumentFilesArea .file-checkbox:checked');
    const bulkPanel = document.getElementById('bulkActionsPanel');
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    const selectedCount = document.getElementById('selectedCount');
    const selectAllLabel = document.querySelector('.select-all-label');
    
    // Show/hide bulk actions panel
    if (checkboxes.length > 0) {
        bulkPanel.style.display = 'block';
        
        // Update selected count
        const count = checkedBoxes.length;
        selectedCount.textContent = `${count} выбрано`;
        
        // Enable/disable bulk delete button
        bulkDeleteBtn.disabled = count === 0;
        
        // Update select all text
        if (count === checkboxes.length && checkboxes.length > 0) {
            selectAllLabel.textContent = 'Снять выделение';
        } else {
            selectAllLabel.textContent = 'Выбрать все';
        }
    } else {
        bulkPanel.style.display = 'none';
    }
}

function toggleSelectAllFiles() {
    const checkboxes = document.querySelectorAll('#editDocumentFilesArea .file-checkbox');
    const checkedBoxes = document.querySelectorAll('#editDocumentFilesArea .file-checkbox:checked');
    const allSelected = checkedBoxes.length === checkboxes.length && checkboxes.length > 0;
    
    checkboxes.forEach(checkbox => {
        checkbox.checked = !allSelected;
        const fileItem = checkbox.closest('.file-item');
        if (fileItem) {
            if (!allSelected) {
                fileItem.classList.add('selected');
            } else {
                fileItem.classList.remove('selected');
            }
        }
    });
    
    updateBulkActionsStateAdmin();
}

function setupBulkActionsAdmin() {
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    
    // Bulk delete functionality
    if (bulkDeleteBtn) {
        bulkDeleteBtn.addEventListener('click', function() {
            const checkedBoxes = document.querySelectorAll('#editDocumentFilesArea .file-checkbox:checked');
            if (checkedBoxes.length === 0) return;
            
            if (confirm(`Вы уверены, что хотите удалить ${checkedBoxes.length} файл(ов)?`)) {
                checkedBoxes.forEach(checkbox => {
                    const fileItem = checkbox.closest('.file-item');
                    if (fileItem) {
                        const removeBtn = fileItem.querySelector('.btn-remove-file');
                        if (removeBtn) {
                            removeBtn.click();
                        }
                    }
                });
                updateBulkActionsStateAdmin();
            }
        });
    }
}

// Admin versions of functions for document modal management

// Open add document modal for admin
function openAddDocumentModalAdmin() {
    const modal = document.getElementById('documentModal');
    if (modal) {
        modal.style.display = 'block';
        
        // Trigger modal opened event
        const event = new CustomEvent('modalOpened');
        modal.dispatchEvent(event);
    }
}

// Load document types for admin
async function loadDocumentTypesAdmin() {
    console.log('Starting to load document types...');
    const documentTypeSelect = document.getElementById('documentTypeSelect');
    
    if (!documentTypeSelect) {
        console.error('Document type select element not found');
        return;
    }
    
    try {
        console.log('Sending request to /document-types...');
        const response = await fetch('/document-types');
        console.log('Response status:', response.status);
        console.log('Response OK:', response.ok);
        
        if (!response.ok) {
            throw new Error(`Failed to load document types: ${response.status} ${response.statusText}`);
        }
        
        const documentTypes = await response.json();
        console.log('Document types received:', documentTypes);
        
        // Clear existing options except the first one
        documentTypeSelect.innerHTML = '<option value="">Выберите тип документа</option>';
        
        // Add document types
        documentTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type.id;
            option.textContent = type.name;  
            option.dataset.documentType = JSON.stringify(type);
            documentTypeSelect.appendChild(option);
        });
        
    } catch (error) {
        console.error('Error loading document types:', error);
        console.error('Error details:', error.message);
        alert('Ошибка загрузки типов документов: ' + error.message);
    }
}

// Load available services for admin
async function loadAvailableServicesAdmin() {
    console.log('Starting to load available services...');
    const servicesSelect = document.getElementById('allowedServicesSelect');
    
    if (!servicesSelect) {
        console.error('Services select element not found');
        return;
    }
    
    try {
        console.log('Sending request to /services...');
        const response = await fetch('/services');
        console.log('Response status:', response.status);
        console.log('Response OK:', response.ok);
        
        if (!response.ok) {
            throw new Error(`Failed to load services: ${response.status} ${response.statusText}`);
        }
        
        const services = await response.json();
        console.log('Services received:', services);
        
        // Clear existing options
        servicesSelect.innerHTML = '';
        
        // Add services
        services.forEach(service => {
            const option = document.createElement('option');
            option.value = service.key;
            option.textContent = `${service.name} - ${service.description}`;
            servicesSelect.appendChild(option);
        });
        
        console.log('Services loaded successfully');
        
    } catch (error) {
        console.error('Error loading services:', error);
        console.error('Error details:', error.message);
        alert('Ошибка загрузки сервисов: ' + error.message);
    }
}

// Handle document type change for admin
function handleDocumentTypeChangeAdmin(event) {
    console.log('Document type changed to:', event.target.value);
    
    const selectedValue = event.target.value;
    const documentFields = document.getElementById('documentFields');
    const newFilesArea = document.getElementById('newDocumentFilesArea');
    const fileInput = document.getElementById('documentFile');
    
    if (!documentFields) {
        console.error('Document fields container not found');
        return;
    }
    
    // Clear existing fields
    documentFields.innerHTML = '';
    
    if (!selectedValue) {
        // No document type selected - disable file area
        if (newFilesArea) {
            newFilesArea.style.opacity = '0.5';
            newFilesArea.style.pointerEvents = 'none';
            newFilesArea.classList.add('disabled');
        }
        if (fileInput) {
            fileInput.disabled = true;
        }
        return;
    }
    
    // Enable file area when document type is selected
    if (newFilesArea) {
        newFilesArea.style.opacity = '1';
        newFilesArea.style.pointerEvents = 'auto';
        newFilesArea.classList.remove('disabled');
    }
    if (fileInput) {
        fileInput.disabled = false;
    }
    
    // Get document type data
    const selectedOption = event.target.selectedOptions[0];
    if (selectedOption && selectedOption.dataset.documentType) {
        try {
            const documentType = JSON.parse(selectedOption.dataset.documentType);
            console.log('Document type data:', documentType);
            
            // Load fields for this document type
            loadDocumentFieldsAdmin(documentFields, documentType.id, {});
            
        } catch (error) {
            console.error('Error parsing document type data:', error);
        }
    }
}

// Load document fields for admin
async function loadDocumentFieldsAdmin(container, documentTypeId, existingData = {}) {
    console.log('Loading fields for document type:', documentTypeId, 'with data:', existingData);
    
    try {
        // Get document types to find the fields for this type
        const response = await fetch('/document-types');
        if (!response.ok) {
            throw new Error(`Failed to load document types: ${response.status}`);
        }
        
        const documentTypes = await response.json();
        const typeData = documentTypes.find(type => type.id === documentTypeId);
        
        if (!typeData || !typeData.fields) {
            container.innerHTML = '<p>Поля для данного типа документа не найдены</p>';
            return;
        }
        
        console.log('Document type fields:', typeData.fields);
        
        container.innerHTML = '';
        
        if (typeData.fields && typeData.fields.length > 0) {
            typeData.fields.forEach(field => {
                const fieldElement = createFieldElementAdmin(field, existingData[field.id] || '');
                container.appendChild(fieldElement);
            });
        }
        
    } catch (error) {
        console.error('Error loading document fields:', error);
        container.innerHTML = '<p>Ошибка загрузки полей документа: ' + error.message + '</p>';
    }
}

// Create field element for admin
function createFieldElementAdmin(field, value = '') {
    const div = document.createElement('div');
    div.className = 'form-group';
    
    const label = document.createElement('label');
    label.textContent = field.label;
    label.setAttribute('for', field.id);
    
    let input;
    if (field.type === 'textarea') {
        input = document.createElement('textarea');
        input.rows = 3;
        input.placeholder = field.placeholder || `Введите ${field.label.toLowerCase()}`;
    } else if (field.type === 'select' && field.options) {
        input = document.createElement('select');
        
        // Add default option
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = `Выберите ${field.label.toLowerCase()}`;
        defaultOption.disabled = true;
        defaultOption.selected = !value;
        input.appendChild(defaultOption);
        
        field.options.forEach(optionText => {
            const option = document.createElement('option');
            option.value = optionText;
            option.textContent = optionText;
            if (value === optionText) {
                option.selected = true;
            }
            input.appendChild(option);
        });
    } else {
        input = document.createElement('input');
        input.type = field.type || 'text';
        input.placeholder = field.placeholder || `Введите ${field.label.toLowerCase()}`;
    }
    
    input.id = field.id;
    input.name = field.id;
    input.value = value;
    
    if (field.required) {
        input.required = true;
        label.innerHTML += ' <span class="required">*</span>';
    }
    
    // Apply formatting if available FROM DATABASE
    if (field.format) {
        console.log('Applying format from database for field:', field.id, field.format);
        applyFieldFormattingAdmin(input, field.format);
    } else {
        console.log('No format found for field:', field.id);
        // Apply basic validation for fields without formatting
        input.addEventListener('input', function(e) {
            validateFieldStateAdmin(e.target, e.target.value, null);
        });
        
        input.addEventListener('blur', function(e) {
            validateFieldStateAdmin(e.target, e.target.value, null);
        });
        
        input.addEventListener('focus', function(e) {
            const formGroup = e.target.closest('.form-group');
            if (formGroup) {
                formGroup.classList.remove('has-error', 'show-format-hint', 'show-required-error');
                e.target.setCustomValidity('');
            }
        });
    }
    
    div.appendChild(label);
    div.appendChild(input);
    
    return div;
}

// Apply field formatting based on format configuration - COPIED FROM PROFILE.JS
function applyFieldFormattingAdmin(input, format) {
    if (!format) return;
    
    // Apply input mask
    if (format.mask) {
        const applyMask = function(e) {
            const rawValue = e.target.value.replace(/[^\w]/g, ''); // Remove non-alphanumeric
            const mask = format.mask;
            let formatted = '';
            let valueIndex = 0;
            
            for (let i = 0; i < mask.length && valueIndex < rawValue.length; i++) {
                if (mask[i] === '9') {
                    if (/\d/.test(rawValue[valueIndex])) {
                        formatted += rawValue[valueIndex];
                        valueIndex++;
                    } else {
                        break;
                    }
                } else if (mask[i] === 'A') {
                    if (/[A-Za-z]/.test(rawValue[valueIndex])) {
                        formatted += rawValue[valueIndex].toUpperCase();
                        valueIndex++;
                    } else {
                        break;
                    }
                } else {
                    formatted += mask[i];
                }
            }
            
            e.target.value = formatted;
            
            // Trigger validation with new logic
            validateFieldStateAdmin(input, formatted, format);
        };
        
        input.addEventListener('input', applyMask);
        input.addEventListener('paste', function(e) {
            setTimeout(() => applyMask(e), 0);
        });
    }
    
    // Apply text transformation
    if (format.transform) {
        input.addEventListener('input', function(e) {
            const value = e.target.value;
            switch (format.transform) {
                case 'uppercase':
                    e.target.value = value.toUpperCase();
                    break;
                case 'lowercase':
                    e.target.value = value.toLowerCase();
                    break;
                case 'capitalize':
                    e.target.value = value.replace(/\b\w/g, l => l.toUpperCase());
                    break;
            }
        });
    }
    
    // Add validation handlers
    input.addEventListener('input', function(e) {
        validateFieldStateAdmin(e.target, e.target.value, format);
    });
    
    input.addEventListener('blur', function(e) {
        validateFieldStateAdmin(e.target, e.target.value, format);
    });
    
    input.addEventListener('focus', function(e) {
        const formGroup = e.target.closest('.form-group');
        if (formGroup) {
            formGroup.classList.remove('has-error', 'show-format-hint', 'show-required-error');
            e.target.setCustomValidity('');
        }
    });
}

// Field validation function for admin - SIMPLIFIED WITHOUT TEXT MESSAGES
function validateFieldStateAdmin(input, value, format) {
    const formGroup = input.closest('.form-group');
    if (!formGroup) return;
    
    // Remove all state classes
    formGroup.classList.remove('has-error', 'has-success', 'show-format-hint', 'show-required-error');
    input.classList.remove('error', 'valid');
    
    // Remove any existing error messages
    const existingError = input.parentNode.querySelector('.validation-error');
    if (existingError) {
        existingError.remove();
    }
    
    // Check if field is empty
    const isEmpty = !value || value.trim() === '';
    
    if (isEmpty) {
        // Empty required field - just red border
        if (input.required) {
            formGroup.classList.add('has-error');
            input.classList.add('error');
            input.setCustomValidity('Обязательно к заполнению');
        }
        return;
    }
    
    // Check format if pattern exists
    if (format && format.pattern) {
        const cleanValue = value.replace(/[^\w]/g, '');
        const regex = new RegExp(format.pattern);
        
        if (regex.test(cleanValue)) {
            // Format is correct - green border
            formGroup.classList.add('has-success');
            input.classList.add('valid');
            input.setCustomValidity('');
        } else {
            // Format is incorrect - red border only
            formGroup.classList.add('has-error');
            input.classList.add('error');
            input.setCustomValidity('Неверный формат данных');
        }
    } else {
        // No pattern, but field is not empty - green border
        formGroup.classList.add('has-success');
        input.classList.add('valid');
        input.setCustomValidity('');
    }
}

// Show field validation error - SIMPLIFIED VERSION WITHOUT TEXT
function showFieldError(input, message) {
    input.classList.add('error');
    // Remove any existing error messages
    const existingError = input.parentNode.querySelector('.validation-error');
    if (existingError) {
        existingError.remove();
    }
    // Don't add text error message, just visual indication
}

// Handle document submission for admin
async function handleDocumentSubmissionAdmin(event) {
    event.preventDefault();
    
    const userId = getCurrentUserIdFromURL();
    if (!userId || userId === 'new') {
        alert('Невозможно добавить документ: пользователь не создан');
        return;
    }
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    
    try {
        // Validate all fields before submission
        const fieldInputs = form.querySelectorAll('#documentFields input, #documentFields select, #documentFields textarea');
        let hasErrors = false;
        
        fieldInputs.forEach(input => {
            // Use the proper validation function
            validateFieldStateAdmin(input, input.value, null);
            
            // Check if field has error class
            const formGroup = input.closest('.form-group');
            if (formGroup && formGroup.classList.contains('has-error')) {
                hasErrors = true;
            }
            
            // Also check custom validity
            if (!input.checkValidity()) {
                hasErrors = true;
            }
        });
        
        if (hasErrors) {
            alert('Пожалуйста, исправьте ошибки в форме перед отправкой');
            return;
        }
        
        // Show loading state
        submitButton.disabled = true;
        submitButton.textContent = 'Добавление...';
        
        const formData = new FormData(form);
        
        // Get document type
        const documentType = formData.get('documentType');
        if (!documentType) {
            throw new Error('Выберите тип документа');
        }
        
        // Collect fields data
        const fields = {};
        fieldInputs.forEach(input => {
            if (input.value.trim()) {
                fields[input.name] = input.value.trim();
            }
        });
        
        // Create document data
        const documentData = {
            document_type: documentType,
            title: documentType, // Use document type as title
            fields: fields
        };
        
        console.log('Submitting document:', documentData);
        
        // Send create document request
        const response = await fetch(`/users/${userId}/documents`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(documentData)
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Ошибка сервера: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('Document created:', result);
        
        // Handle file uploads
        const filesContainer = document.getElementById('newFilesContainer');
        if (filesContainer) {
            const fileItems = filesContainer.querySelectorAll('.file-item[data-status="new"]');
            if (fileItems.length > 0) {
                // Get the latest document index (assuming it's the last one)
                const docIndex = result.document_index || 0;
                
                for (const fileItem of fileItems) {
                    if (fileItem.fileObject) {
                        try {
                            const uploadFormData = new FormData();
                            uploadFormData.append('file', fileItem.fileObject);
                            
                            const uploadResponse = await fetch(`/users/${userId}/documents/${docIndex}/attachments`, {
                                method: 'POST',
                                body: uploadFormData
                            });
                            
                            if (!uploadResponse.ok) {
                                console.warn('File upload failed for:', fileItem.fileObject.name);
                            }
                        } catch (uploadError) {
                            console.error('Error uploading file:', uploadError);
                        }
                    }
                }
            }
        }
        
        alert('Документ успешно добавлен');
        closeDocumentModalAdmin();
        loadUserDocuments(); // Reload documents list
        
    } catch (error) {
        console.error('Error adding document:', error);
        alert('Ошибка при добавлении документа: ' + error.message);
    } finally {
        // Restore button state
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

// Close document modal for admin
function closeDocumentModalAdmin() {
    const modal = document.getElementById('documentModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Update unified area visibility for admin
function updateUnifiedAreaVisibilityAdmin(areaContainer) {
    const filesContainer = areaContainer.querySelector('.files-container');
    const emptyState = areaContainer.querySelector('.empty-files-state');
    
    // Count actual file items (not including add button)
    const fileItems = filesContainer ? filesContainer.querySelectorAll('.file-item') : [];
    const hasFiles = fileItems.length > 0;
    
    if (emptyState) {
        emptyState.style.display = hasFiles ? 'none' : 'block';
    }
    
    if (filesContainer) {
        filesContainer.style.display = hasFiles ? 'flex' : 'none';
    }
}

// Initialize main user form submission handler
function initUserFormHandler() {
    const userForm = document.getElementById('userForm');
    console.log('Looking for userForm:', userForm);
    
    if (!userForm) {
        console.log('userForm not found!');
        return;
    }
    
    console.log('Adding submit event listener to userForm');
    
    userForm.addEventListener('submit', function(e) {
        console.log('Form submit intercepted!');
        e.preventDefault();
        
        const submitButton = userForm.querySelector('button[type="submit"]');
        const originalText = submitButton.textContent;
        
        console.log('Form action:', userForm.action);
        
        // Show loading state
        submitButton.disabled = true;
        submitButton.textContent = 'Сохранение...';
        
        // Create FormData from the form
        const formData = new FormData(userForm);
        
        console.log('Submitting form to:', userForm.action);
        
        // Submit form using fetch
        fetch(userForm.action, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            console.log('Response received:', response);
            return response.json();
        })
        .then(data => {
            console.log('Response data:', data);
            if (data.success && data.redirect) {
                console.log('Redirecting to:', data.redirect);
                
                // Force refresh avatars before redirect to clear cache
                if (window.avatarCropInstance) {
                    console.log('Refreshing avatars before redirect...');
                    window.avatarCropInstance.refreshAllUserAvatars();
                }
                
                // Longer delay to allow avatar refresh and cache clearing
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 500);
            } else if (data.error) {
                alert('Ошибка: ' + data.error);
            } else {
                alert('Произошла неизвестная ошибка');
            }
        })
        .catch(error => {
            console.error('Error submitting form:', error);
            alert('Ошибка при отправке формы: ' + error.message);
        })
        .finally(() => {
            // Restore button state
            submitButton.disabled = false;
            submitButton.textContent = originalText;
        });
    });
}
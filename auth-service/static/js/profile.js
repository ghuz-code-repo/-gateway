document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initModals();
    initDocumentHandlers();
    initNotifications();
    initDocumentModal();
});

// Global flag to prevent modal closing during file operations
let isFileOperationInProgress = false;

// Custom Multiselect Component
class CustomMultiselect {
    constructor(container, options = {}) {
        this.container = container;
        this.options = {
            placeholder: 'Выберите опции...',
            selectAllText: 'Выбрать все',
            noOptionsText: 'Нет доступных опций',
            loadingText: 'Загрузка...',
            errorText: 'Ошибка загрузки',
            ...options
        };
        
        this.selectedValues = new Set();
        this.availableOptions = [];
        this.isOpen = false;
        this.isLoading = false;
        
        this.init();
    }
    
    init() {
        this.toggle = this.container.querySelector('.multiselect-toggle');
        this.dropdown = this.container.querySelector('.multiselect-dropdown');
        this.toggleText = this.container.querySelector('.multiselect-toggle-text');
        this.arrow = this.container.querySelector('.multiselect-arrow');
        
        this.bindEvents();
    }
    
    bindEvents() {
        // Toggle dropdown
        this.toggle.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.toggleDropdown();
        });
        
        // Keyboard support
        this.toggle.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.toggleDropdown();
            }
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.container.contains(e.target)) {
                this.closeDropdown();
            }
        });
    }
    
    toggleDropdown() {
        if (this.isOpen) {
            this.closeDropdown();
        } else {
            this.openDropdown();
        }
    }
    
    openDropdown() {
        this.isOpen = true;
        this.toggle.classList.add('open');
        this.dropdown.classList.add('open');
    }
    
    closeDropdown() {
        this.isOpen = false;
        this.toggle.classList.remove('open');
        this.dropdown.classList.remove('open');
    }
    
    setLoading(loading) {
        this.isLoading = loading;
        if (loading) {
            this.dropdown.innerHTML = `<div class="multiselect-loading">${this.options.loadingText}</div>`;
            this.toggleText.textContent = this.options.loadingText;
            this.toggle.classList.add('disabled');
        } else {
            this.toggle.classList.remove('disabled');
        }
    }
    
    setError(error) {
        this.dropdown.innerHTML = `<div class="multiselect-error">${error || this.options.errorText}</div>`;
        this.toggleText.textContent = this.options.errorText;
    }
    
    setOptions(options) {
        this.availableOptions = options;
        this.renderOptions();
        this.updateToggleText();
    }
    
    renderOptions() {
        if (this.availableOptions.length === 0) {
            this.dropdown.innerHTML = `<div class="multiselect-loading">${this.options.noOptionsText}</div>`;
            return;
        }
        
        let html = '';
        
        // Add "Select All" option
        const allSelected = this.availableOptions.length > 0 && 
                           this.availableOptions.every(opt => this.selectedValues.has(opt.value));
        
        html += `
            <div class="multiselect-option multiselect-select-all">
                <input type="checkbox" 
                       id="select-all-${this.container.id}" 
                       ${allSelected ? 'checked' : ''}>
                <label for="select-all-${this.container.id}" class="multiselect-option-label">
                    ${this.options.selectAllText}
                </label>
            </div>
        `;
        
        // Add individual options
        this.availableOptions.forEach(option => {
            const isSelected = this.selectedValues.has(option.value);
            html += `
                <div class="multiselect-option" data-value="${option.value}">
                    <input type="checkbox" 
                           id="option-${option.value}-${this.container.id}" 
                           ${isSelected ? 'checked' : ''}>
                    <label for="option-${option.value}-${this.container.id}" class="multiselect-option-label">
                        ${option.label}
                    </label>
                </div>
            `;
        });
        
        this.dropdown.innerHTML = html;
        this.bindOptionEvents();
    }
    
    bindOptionEvents() {
        const selectAllCheckbox = this.dropdown.querySelector('.multiselect-select-all input');
        const optionElements = this.dropdown.querySelectorAll('.multiselect-option:not(.multiselect-select-all)');
        
        // Select all functionality
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                const checked = e.target.checked;
                if (checked) {
                    this.selectAll();
                } else {
                    this.deselectAll();
                }
            });
        }
        
        // Individual option functionality
        optionElements.forEach(element => {
            const checkbox = element.querySelector('input');
            const value = element.dataset.value;
            
            element.addEventListener('click', (e) => {
                if (e.target.type !== 'checkbox') {
                    e.preventDefault();
                    checkbox.checked = !checkbox.checked;
                }
                
                if (checkbox.checked) {
                    this.selectValue(value);
                } else {
                    this.deselectValue(value);
                }
            });
            
            checkbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.selectValue(value);
                } else {
                    this.deselectValue(value);
                }
            });
        });
    }
    
    selectValue(value) {
        this.selectedValues.add(value);
        this.updateToggleText();
        this.updateSelectAllCheckbox();
        this.triggerChange();
    }
    
    deselectValue(value) {
        this.selectedValues.delete(value);
        this.updateToggleText();
        this.updateSelectAllCheckbox();
        this.triggerChange();
    }
    
    selectAll() {
        this.availableOptions.forEach(option => {
            this.selectedValues.add(option.value);
        });
        this.renderOptions();
        this.updateToggleText();
        this.triggerChange();
    }
    
    deselectAll() {
        this.selectedValues.clear();
        this.renderOptions();
        this.updateToggleText();
        this.triggerChange();
    }
    
    setSelectedValues(values) {
        this.selectedValues = new Set(values);
        this.renderOptions();
        this.updateToggleText();
    }
    
    getSelectedValues() {
        return Array.from(this.selectedValues);
    }
    
    updateToggleText() {
        const selectedCount = this.selectedValues.size;
        
        if (selectedCount === 0) {
            this.toggleText.textContent = this.options.placeholder;
            this.toggleText.classList.add('placeholder');
        } else if (selectedCount === 1) {
            const selectedOption = this.availableOptions.find(opt => this.selectedValues.has(opt.value));
            this.toggleText.textContent = selectedOption ? selectedOption.label : `${selectedCount} выбрано`;
            this.toggleText.classList.remove('placeholder');
        } else if (selectedCount === this.availableOptions.length && this.availableOptions.length > 0) {
            this.toggleText.textContent = 'Все выбраны';
            this.toggleText.classList.remove('placeholder');
        } else {
            this.toggleText.textContent = `${selectedCount} выбрано`;
            this.toggleText.classList.remove('placeholder');
        }
    }
    
    updateSelectAllCheckbox() {
        const selectAllCheckbox = this.dropdown.querySelector('.multiselect-select-all input');
        if (selectAllCheckbox) {
            const allSelected = this.availableOptions.length > 0 && 
                               this.availableOptions.every(opt => this.selectedValues.has(opt.value));
            selectAllCheckbox.checked = allSelected;
        }
    }
    
    triggerChange() {
        const event = new CustomEvent('multiselect:change', {
            detail: {
                selectedValues: this.getSelectedValues(),
                selectedOptions: this.availableOptions.filter(opt => this.selectedValues.has(opt.value))
            }
        });
        this.container.dispatchEvent(event);
    }
    
    destroy() {
        // Clean up event listeners if needed
        this.closeDropdown();
    }
}

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

    // // Close modal on backdrop click
    // modals.forEach(modal => {
    //     modal.addEventListener('click', (e) => {
    //         if (e.target === modal && !isFileOperationInProgress) {
    //             closeModal(modal);
    //         }
    //     });
    // });

    // Close modal on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !isFileOperationInProgress) {
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
    
    // Trigger modalOpened event for custom handlers
    const modalOpenedEvent = new CustomEvent('modalOpened', { bubbles: true });
    modal.dispatchEvent(modalOpenedEvent);
    
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

    // Document action handlers - use more specific selectors and event delegation
    console.log('Setting up document click handlers');
    document.addEventListener('click', (e) => {
        // Check if clicked element or its parent has the required class
        const deleteBtn = e.target.closest('.btn-delete-doc');
        const editBtn = e.target.closest('.btn-edit-doc');
        const downloadBtn = e.target.closest('.btn-download-doc');
        const downloadAttachmentsBtn = e.target.closest('.btn-download-attachments');
        
        if (deleteBtn) {
            console.log('Delete button clicked');
            handleDocumentDelete(e);
        } else if (editBtn) {
            console.log('Edit button clicked, docId:', editBtn.dataset.docId);
            handleDocumentEdit(e);
        } else if (downloadBtn) {
            console.log('Download button clicked');
            handleDocumentDownload(e);
        } else if (downloadAttachmentsBtn) {
            console.log('Download attachments button clicked');
            handleDownloadAttachments(e);
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

async function handleDocumentEdit(e) {
    e.preventDefault();
    const docId = e.target.dataset.docId;
    
    console.log('handleDocumentEdit called with docId:', docId);
    
    if (!docId) {
        console.error('Document ID not found');
        return;
    }

    try {
        // Add loading state to button
        const originalContent = e.target.innerHTML;
        e.target.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        e.target.disabled = true;

        // Load document data from server
        const response = await fetch(`/profile/documents/${docId}`);
        if (!response.ok) {
            throw new Error(`Failed to load document: ${response.status}`);
        }

        const docData = await response.json();
        
        // Open edit modal and populate with data
        await openEditDocumentModal(docData);

        // Restore button state
        e.target.innerHTML = originalContent;
        e.target.disabled = false;

    } catch (error) {
        console.error('Error loading document for edit:', error);
        showNotification('Ошибка загрузки документа', 'error');
        
        // Restore button state
        e.target.innerHTML = originalContent || '<i class="fas fa-edit"></i>';
        e.target.disabled = false;
    }
}

async function openEditDocumentModal(docData) {
    const editModal = document.getElementById('editDocumentModal');
    if (!editModal) {
        console.error('Edit document modal not found');
        return;
    }

    // Set document ID
    const docIdInput = editModal.querySelector('#editDocumentId');
    if (docIdInput) {
        docIdInput.value = docData.id;
    }

    // Load document types and set current type
    const typeSelect = editModal.querySelector('#editDocumentTypeSelect');
    if (typeSelect) {
        await loadDocumentTypesForEdit(typeSelect, docData.document_type);
    }

    // Load available services and set selected ones
    const servicesContainer = editModal.querySelector('#editAllowedServicesMultiselect');
    if (servicesContainer) {
        await loadAvailableServicesForEdit(servicesContainer, docData.allowed_services || []);
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
        console.log('Loading attachments for document:', docData.id);
        await loadDocumentAttachments(docData.id, unifiedArea);
        setupUnifiedFilesArea(unifiedArea);
    } else {
        console.error('Unified files area not found!');
    }

    // Open the modal
    openModal(editModal);
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

async function handleDownloadAttachments(e) {
    e.preventDefault();
    const docId = e.target.closest('.btn-download-attachments').dataset.docId;
    
    if (!docId) {
        showNotification('ID документа не найден', 'error');
        return;
    }
    
    // Add loading state
    const button = e.target.closest('.btn-download-attachments');
    const originalContent = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    button.disabled = true;
    
    try {
        // Get attachments list first
        const response = await fetch(`/profile/documents/${docId}/attachments`);
        if (!response.ok) {
            throw new Error('Не удалось получить список вложений');
        }
        
        const attachments = await response.json();
        if (!attachments || attachments.length === 0) {
            throw new Error('У документа нет вложений для скачивания');
        }
        
        // Download each attachment
        for (const attachment of attachments) {
            try {
                // Create a temporary link and click it to download
                const link = document.createElement('a');
                link.href = `/profile/documents/${docId}/attachments/${attachment.id}/download`;
                link.download = attachment.original_name || attachment.filename;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                // Small delay between downloads to avoid overwhelming the browser
                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (err) {
                console.error('Error downloading attachment:', attachment.filename, err);
            }
        }
        
        showNotification(`Скачивание ${attachments.length} файлов началось`, 'success');
        
    } catch (error) {
        console.error('Error downloading attachments:', error);
        showNotification(error.message || 'Ошибка при скачивании вложений', 'error');
    } finally {
        // Reset button
        setTimeout(() => {
            button.innerHTML = originalContent;
            button.disabled = false;
        }, 1000);
    }
}

// File Management Functions
async function loadDocumentAttachments(docId, container) {
    try {
        const response = await fetch(`/profile/documents/${docId}/attachments`);
        if (!response.ok) {
            if (response.status === 404) {
                updateUnifiedFilesArea(container, []);
                return;
            }
            throw new Error(`Failed to load attachments: ${response.status}`);
        }
        
        const attachments = await response.json();
        updateUnifiedFilesArea(container, attachments || [], docId);
        
    } catch (error) {
        console.error('Error loading document attachments:', error);
        updateUnifiedFilesArea(container, []);
    }
}

function updateUnifiedFilesArea(areaContainer, attachments = [], docId = null) {
    console.log('updateUnifiedFilesArea called with:', areaContainer, attachments);
    const filesContainer = areaContainer.querySelector('.files-container');
    
    if (!filesContainer) {
        console.error('Files container not found in unified area');
        return;
    }
    
    // Clear all existing files (both uploaded and new)
    filesContainer.innerHTML = '';
    
    // Also clear the file input to reset it
    const fileInput = areaContainer.parentElement.querySelector('#editDocumentFiles');
    if (fileInput) {
        fileInput.value = '';
    }
    
    // Add uploaded files
    attachments.forEach(attachment => {
        const fileItem = createUnifiedFileItem(attachment, 'uploaded', docId);
        filesContainer.appendChild(fileItem);
    });
    
    // Add "+" button inside files container if there are files
    if (attachments.length > 0) {
        const addButton = createAddFileButton(areaContainer);
        filesContainer.appendChild(addButton);
    }
    
    // Update visibility states
    updateUnifiedAreaVisibility(areaContainer);
    
    // Update bulk actions state if this is the edit modal
    if (areaContainer.id === 'editDocumentFilesArea') {
        setTimeout(updateBulkActionsState, 0);
    }
}

function createUnifiedFileItem(fileData, status = 'uploaded', docId = null) {
    const div = document.createElement('div');
    div.className = 'file-item';
    div.dataset.fileId = fileData.id || fileData.name;
    div.dataset.status = status;
    
    // Store file object for new files
    if (status === 'new' && fileData instanceof File) {
        div.fileObject = fileData;
    }
    
    const isImage = /\.(jpg|jpeg|png|gif)$/i.test(fileData.filename || fileData.name);
    const isPdf = /\.pdf$/i.test(fileData.filename || fileData.name);
    
    let previewContent = '';
    if (isImage && status === 'uploaded') {
        const previewUrl = `/profile/documents/${docId}/attachments/${fileData.id}/preview`;
        console.log('Creating preview for uploaded image:', {
            fileName: fileData.filename || fileData.name,
            docId,
            attachmentId: fileData.id,
            previewUrl
        });
        previewContent = `<img src="${previewUrl}" alt="${fileData.filename || fileData.name}" 
                               onload="console.log('Image loaded successfully:', '${previewUrl}')"
                               onerror="console.log('Image failed to load:', '${previewUrl}'); this.style.display='none'; this.nextElementSibling.style.display='block';">
                         <i class="fas fa-file-image" style="display: none; color: #28a745;"></i>`;
    } else if (isImage && status === 'new') {
        // For new files, we'll set the src via FileReader
        previewContent = `<img class="preview-placeholder" alt="${fileData.name}">`;
    } else if (isPdf) {
        previewContent = `<i class="fas fa-file-pdf" style="color: #dc3545;"></i>`;
    } else {
        previewContent = `<i class="fas fa-file"></i>`;
    }
    
    const statusIcon = status === 'uploaded' ? 'fa-save' : 'fa-plus';
    const statusTitle = status === 'uploaded' ? 'Загружен' : 'Новый файл';
    
    // Generate preview button HTML if needed
    const canPreview = (status === 'uploaded' && docId) || (status === 'new');
    
    // For new files, create a simplified data structure for the button
    let buttonFileData;
    if (status === 'new' && fileData instanceof File) {
        buttonFileData = {
            name: fileData.name,
            size: fileData.size,
            type: fileData.type,
            lastModified: fileData.lastModified
        };
    } else {
        buttonFileData = fileData;
    }
    
    const previewButtonHTML = canPreview ? `
        <div class="file-preview-button">
            <button type="button" class="btn-preview-file" data-doc-id="${docId || ''}" data-file-data="${encodeURIComponent(JSON.stringify(buttonFileData))}" data-status="${status}" onclick="previewAttachmentFromButton(this, event)" title="Предпросмотр">
                <i class="fas fa-eye"></i>
                <span>Предпросмотр</span>
            </button>
        </div>
    ` : '';
    
    console.log('Preview button HTML generation:', { 
        status, 
        docId, 
        willCreateButton: canPreview,
        filename: fileData.filename || fileData.name,
        buttonFileData: buttonFileData
    });
    
    div.innerHTML = `
        <div class="file-item-checkbox">
            <input type="checkbox" class="file-checkbox" data-file-id="${fileData.id || fileData.name}" data-status="${status}">
        </div>
        <div class="file-item-preview">
            ${previewContent}
        </div>
        <div class="file-item-info">
            ${fileData.filename || fileData.name}
            ${previewButtonHTML}
        </div>
        <div class="file-item-status ${status}" title="${statusTitle}">
            <i class="fas ${statusIcon}"></i>
        </div>
        <div class="file-item-actions">
            <button type="button" class="file-item-action file-delete-btn" onclick="removeFileItem(this, event)" title="Удалить">
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
    
    return div;
}

function previewAttachmentFromButton(button, event) {
    console.log('Preview button clicked:', button);
    // Prevent form submission
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    const docId = button.dataset.docId;
    const fileDataEncoded = button.dataset.fileData;
    const status = button.dataset.status;
    
    console.log('Preview data:', { docId, fileDataEncoded, status });
    
    try {
        const fileData = JSON.parse(decodeURIComponent(fileDataEncoded));
        console.log('Parsed file data:', fileData);
        
        if (status === 'uploaded') {
            // For uploaded files, use server preview
            console.log('Calling previewAttachment for uploaded file');
            previewAttachment(docId, fileData);
        } else if (status === 'new') {
            // For new files, use local preview
            console.log('Calling previewNewFile for new file');
            previewNewFile(fileData);
        }
    } catch (error) {
        console.error('Error parsing file data for preview:', error);
        showNotification('Ошибка открытия предпросмотра', 'error');
    }
}

function createAddFileButton(areaContainer) {
    const button = document.createElement('div');
    button.className = 'add-file-button';
    button.innerHTML = '<i class="fas fa-plus"></i>';
    
    // Add click handler
    button.addEventListener('click', () => {
        const fileInput = areaContainer.parentElement.querySelector('#editDocumentFiles, #documentFile');
        if (fileInput) {
            fileInput.click();
        }
    });
    
    return button;
}

function updateUnifiedAreaVisibility(areaContainer) {
    const filesContainer = areaContainer.querySelector('.files-container');
    const emptyState = areaContainer.querySelector('.empty-files-state');
    
    // Count actual file items (not including add button)
    const fileItems = filesContainer ? filesContainer.querySelectorAll('.file-item') : [];
    const hasFiles = fileItems.length > 0;
    
    if (emptyState) {
        emptyState.style.display = hasFiles ? 'none' : 'block';
    }
}

function setupUnifiedFilesArea(areaContainer) {
    const fileInput = areaContainer.parentElement.querySelector('#editDocumentFiles, #documentFile');
    const emptyState = areaContainer.querySelector('.empty-files-state');
    
    if (!fileInput) {
        console.error('File input not found for unified files area');
        return;
    }
    
    // Check if already initialized to prevent duplicate handlers
    if (areaContainer.dataset.initialized === 'true') {
        return;
    }
    
    // Handle click events for file selection on empty state
    if (emptyState) {
        emptyState.addEventListener('click', () => {
            fileInput.click();
        });
    }
    
    // Handle file input change
    fileInput.addEventListener('change', (e) => {
        handleUnifiedFilesChange(e, areaContainer);
        // Clear the input after processing to prevent issues
        e.target.value = '';
    });
    
    // Handle drag and drop
    areaContainer.addEventListener('dragover', (e) => {
        e.preventDefault();
        areaContainer.classList.add('dragover');
    });
    
    areaContainer.addEventListener('dragleave', (e) => {
        if (!areaContainer.contains(e.relatedTarget)) {
            areaContainer.classList.remove('dragover');
        }
    });
    
    areaContainer.addEventListener('drop', (e) => {
        e.preventDefault();
        areaContainer.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            // Simulate file input change event with dropped files
            handleUnifiedFilesChange({ target: { files: files } }, areaContainer);
        }
    });
    
    // Mark as initialized
    areaContainer.dataset.initialized = 'true';
}

function handleUnifiedFilesChange(event, areaContainer) {
    isFileOperationInProgress = true;
    
    const files = event.target.files;
    if (!files || files.length === 0) {
        isFileOperationInProgress = false;
        return;
    }
    
    const filesContainer = areaContainer.querySelector('.files-container');
    if (!filesContainer) return;
    
    // Add new files to the unified area
    Array.from(files).forEach((file) => {
        console.log('Creating file item for:', file.name, file);
        const fileItem = createUnifiedFileItem(file, 'new');
        
        // Store the File object in the file item for preview functionality
        fileItem.fileObject = file;
        console.log('File object stored in element:', fileItem.fileObject);
        
        // For image files, set up preview
        if (file.type.startsWith('image/')) {
            const img = fileItem.querySelector('.preview-placeholder');
            if (img) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    img.src = e.target.result;
                };
                reader.readAsDataURL(file);
            }
        }
        
        // Insert before add button if it exists, otherwise just append
        const addButton = filesContainer.querySelector('.add-file-button');
        if (addButton) {
            filesContainer.insertBefore(fileItem, addButton);
        } else {
            filesContainer.appendChild(fileItem);
        }
    });
    
    // Ensure add button exists and is at the end
    let addButton = filesContainer.querySelector('.add-file-button');
    if (!addButton) {
        addButton = createAddFileButton(areaContainer);
        filesContainer.appendChild(addButton);
    }
    
    updateUnifiedAreaVisibility(areaContainer);
    
    // Reset file operation flag after a short delay
    setTimeout(() => {
        isFileOperationInProgress = false;
    }, 100);
}

function removeFileItem(button, event) {
    // Prevent form submission
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    const fileItem = button.closest('.file-item');
    if (!fileItem) return;
    
    const status = fileItem.dataset.status;
    
    if (status === 'uploaded') {
        // For uploaded files, call remove API
        const docId = getCurrentEditingDocumentId();
        const fileId = fileItem.dataset.fileId;
        if (docId && fileId) {
            removeAttachment(docId, fileId, false); // false = show confirmation
        }
    } else {
        // For new files, show confirmation then remove from DOM
        if (!confirm('Удалить этот файл?')) {
            return;
        }
        
        isFileOperationInProgress = true;
        
        const areaContainer = fileItem.closest('.unified-files-area');
        fileItem.remove();
        
        // Check if we need to remove add button (if no files left)
        if (areaContainer) {
            const filesContainer = areaContainer.querySelector('.files-container');
            const fileItems = filesContainer ? filesContainer.querySelectorAll('.file-item') : [];
            
            if (fileItems.length === 0) {
                const addButton = filesContainer.querySelector('.add-file-button');
                if (addButton) {
                    addButton.remove();
                }
            }
            
            updateUnifiedAreaVisibility(areaContainer);
        }
        
        // Reset flag after operation
        setTimeout(() => {
            isFileOperationInProgress = false;
        }, 100);
    }
}

function getCurrentEditingDocumentId() {
    const editModal = document.getElementById('editDocumentModal');
    if (editModal) {
        const docIdInput = editModal.querySelector('#editDocumentId');
        return docIdInput ? docIdInput.value : null;
    }
    return null;
}

function createAttachmentElement(attachment, docId) {
    const div = document.createElement('div');
    div.className = 'attached-file';
    
    const isImage = /\.(jpg|jpeg|png|gif)$/i.test(attachment.filename);
    const isPdf = /\.pdf$/i.test(attachment.filename);
    
    let previewContent = '';
    if (isImage) {
        // Use direct file path for image preview
        previewContent = `<img src="${attachment.file_path}" class="file-preview-image" alt="${attachment.filename}">`;
    } else if (isPdf) {
        previewContent = `<div class="file-preview-pdf"><i class="fas fa-file-pdf"></i></div>`;
    } else {
        previewContent = `<div class="file-preview-placeholder"><i class="fas fa-file"></i></div>`;
    }
    
    div.innerHTML = `
        ${previewContent}
        <div class="attached-file-name">${attachment.filename}</div>
        <div class="attached-file-size">${formatFileSize(attachment.size || 0)}</div>
        <button class="attached-file-download" onclick="downloadAttachment('${docId}', '${attachment.id}')" title="Скачать">
            <i class="fas fa-download"></i>
        </button>
        <button class="attached-file-remove" onclick="removeAttachment('${docId}', '${attachment.id}')" title="Удалить">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add click event for preview
    div.addEventListener('click', (e) => {
        if (!e.target.closest('button')) {
            previewAttachment(docId, attachment);
        }
    });
    
    return div;
}

function handleFilePreview(event, previewContainerSelector) {
    const files = event.target.files;
    const container = document.querySelector(previewContainerSelector);
    
    if (!container) {
        console.error('Preview container not found:', previewContainerSelector);
        return;
    }
    
    // Clear previous previews
    container.innerHTML = '';
    
    if (!files || files.length === 0) {
        return;
    }
    
    Array.from(files).forEach((file, index) => {
        const previewElement = createFilePreviewElement(file, index, previewContainerSelector);
        container.appendChild(previewElement);
    });
}

function createFilePreviewElement(file, index, containerSelector) {
    const div = document.createElement('div');
    div.className = 'file-preview';
    div.dataset.fileIndex = index;
    
    const isImage = file.type.startsWith('image/');
    const isPdf = file.type === 'application/pdf';
    
    let previewContent = '';
    if (isImage) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = div.querySelector('.file-preview-image');
            if (img) {
                img.src = e.target.result;
            }
        };
        reader.readAsDataURL(file);
        previewContent = `<img class="file-preview-image" alt="${file.name}">`;
    } else if (isPdf) {
        previewContent = `<div class="file-preview-pdf"><i class="fas fa-file-pdf"></i></div>`;
    } else {
        previewContent = `<div class="file-preview-placeholder"><i class="fas fa-file"></i></div>`;
    }
    
    div.innerHTML = `
        ${previewContent}
        <div class="file-preview-name">${file.name}</div>
        <div class="file-preview-size">${formatFileSize(file.size)}</div>
        <button class="file-preview-remove" onclick="removeFilePreview(${index}, '${containerSelector}')" title="Удалить">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    return div;
}

function removeFilePreview(index, containerSelector) {
    const container = document.querySelector(containerSelector);
    const preview = container.querySelector(`[data-file-index="${index}"]`);
    
    if (preview) {
        preview.remove();
        
        // Update file input to remove the file
        const fileInput = container.closest('.modal').querySelector('input[type="file"]');
        if (fileInput && fileInput.files) {
            const dt = new DataTransfer();
            Array.from(fileInput.files).forEach((file, i) => {
                if (i !== index) {
                    dt.items.add(file);
                }
            });
            fileInput.files = dt.files;
            
            // Update remaining indices
            const remainingPreviews = container.querySelectorAll('.file-preview');
            remainingPreviews.forEach((preview, newIndex) => {
                preview.dataset.fileIndex = newIndex;
                const removeBtn = preview.querySelector('.file-preview-remove');
                if (removeBtn) {
                    removeBtn.setAttribute('onclick', `removeFilePreview(${newIndex}, '${containerSelector}')`);
                }
            });
        }
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function downloadAttachment(docId, attachmentId) {
    try {
        window.open(`/profile/documents/${docId}/attachments/${attachmentId}/download`, '_blank');
    } catch (error) {
        console.error('Error downloading attachment:', error);
        showNotification('Ошибка скачивания файла', 'error');
    }
}

async function removeAttachment(docId, attachmentId, skipConfirm = false) {
    if (!skipConfirm && !confirm('Удалить этот файл?')) {
        return false;
    }
    
    isFileOperationInProgress = true;
    
    try {
        const response = await fetch(`/profile/documents/${docId}/attachments/${attachmentId}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            throw new Error(`Failed to remove attachment: ${response.status}`);
        }
        
        showNotification('Файл удален', 'success');
        
        // Only update the specific file item instead of reloading everything
        const fileItem = document.querySelector(`[data-file-id="${attachmentId}"]`);
        if (fileItem) {
            const areaContainer = fileItem.closest('.unified-files-area');
            fileItem.remove();
            
            // Update visibility after removing file
            if (areaContainer) {
                updateUnifiedAreaVisibility(areaContainer);
                
                // Check if we need to remove add button (if no files left)
                const filesContainer = areaContainer.querySelector('.files-container');
                const fileItems = filesContainer ? filesContainer.querySelectorAll('.file-item') : [];
                
                if (fileItems.length === 0) {
                    const addButton = filesContainer.querySelector('.add-file-button');
                    if (addButton) {
                        addButton.remove();
                    }
                } else if (fileItems.length > 0 && !filesContainer.querySelector('.add-file-button')) {
                    // Add the + button back if there are files but no button
                    const addButton = createAddFileButton(areaContainer);
                    filesContainer.appendChild(addButton);
                }
                
                // Update bulk actions state if this is the edit modal
                if (areaContainer.id === 'editDocumentFilesArea') {
                    setTimeout(updateBulkActionsState, 0);
                }
            }
        }
        
        return true;
        
    } catch (error) {
        console.error('Error removing attachment:', error);
        showNotification('Ошибка удаления файла', 'error');
        return false;
    } finally {
        isFileOperationInProgress = false;
    }
}

function previewAttachment(docId, attachment) {
    console.log('previewAttachment called with:', { docId, attachment });
    isFileOperationInProgress = true;
    
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
        downloadAttachment(docId, attachment.id);
    }
    
    // Reset flag after a short delay
    setTimeout(() => {
        isFileOperationInProgress = false;
    }, 100);
}

function previewNewFile(fileData) {
    isFileOperationInProgress = true;
    
    console.log('Preview new file data:', fileData);
    
    // For new files, we need to access the actual File object
    const searchId = fileData.name; // For new files, always use name as identifier
    console.log('Searching for element with data-file-id:', searchId);
    
    // Find file item by name (since new files use name as file-id)
    const fileItem = document.querySelector(`.file-item[data-file-id="${searchId}"][data-status="new"]`);
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
            console.log('Checking item with data-file-id:', item.dataset.fileId, 'fileObject:', item.fileObject);
            if (item.fileObject && item.fileObject.name === searchId) {
                foundItem = item;
            }
        });
        
        if (foundItem && foundItem.fileObject) {
            console.log('Found file via manual search:', foundItem.fileObject);
            previewFileObject(foundItem.fileObject);
        } else {
            showNotification('Файл недоступен для предпросмотра', 'error');
        }
        
        setTimeout(() => {
            isFileOperationInProgress = false;
        }, 100);
        return;
    }
    
    previewFileObject(fileObject);
    
    // Reset flag after a short delay
    setTimeout(() => {
        isFileOperationInProgress = false;
    }, 100);
}

function previewFileObject(fileObject) {
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
        showNotification('Файл скачан', 'success');
    }
}

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
                <iframe src="${src}" type="application/pdf"></iframe>
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
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || data.message || 'Ошибка сервера');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success || data.message) {
                const message = data.message || 'Профиль успешно обновлен';
                showNotification(message, 'success');
                // Update displayed information if needed
                if (data.user) {
                    updateProfileDisplay(data.user);
                }
                // Reset password form if it's a password change
                if (e.target.id === 'passwordForm') {
                    e.target.reset();
                    // Clear validation states
                    const formGroups = e.target.querySelectorAll('.form-group');
                    formGroups.forEach(group => {
                        group.classList.remove('has-error', 'has-success');
                    });
                }
            } else {
                showNotification(data.error || data.message || 'Ошибка при сохранении профиля', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification(error.message || 'Ошибка при сохранении профиля', 'error');
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
    
    // Update name displays
    const nameDisplay = document.querySelector('.info-group .info-item[data-field="name"]');
    if (nameDisplay && userData.fullName) {
        nameDisplay.textContent = userData.fullName;
    }
    
    // Update header name if exists
    const headerName = document.querySelector('.user-name, .header-user-name');
    if (headerName && userData.shortName) {
        headerName.textContent = userData.shortName;
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

// Document Modal Functions
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
        loadDocumentTypes();
        loadAvailableServices();
        
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
            updateUnifiedAreaVisibility(newFilesArea);
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
    documentTypeSelect.addEventListener('change', handleDocumentTypeChange);
    
    // Handle form submission
    documentForm.addEventListener('submit', handleDocumentSubmission);
    
    // Initialize unified files area for create modal
    const newFilesArea = document.getElementById('newDocumentFilesArea');
    const fileInput = document.getElementById('documentFile');
    if (newFilesArea) {
        setupUnifiedFilesArea(newFilesArea);
        // Initially disable files area until document type is selected
        newFilesArea.style.opacity = '0.5';
        newFilesArea.style.pointerEvents = 'none';
        newFilesArea.classList.add('disabled');
    }
    if (fileInput) {
        fileInput.disabled = true;
    }
    
    // Initialize edit document modal
    initEditDocumentModal();
}

function initEditDocumentModal() {
    const editDocumentForm = document.getElementById('editDocumentForm');
    const cancelEditBtn = document.getElementById('cancelEditDocumentBtn');
    
    if (!editDocumentForm) {
        console.warn('Edit document form not found');
        return;
    }
    
    // Handle form submission for editing
    editDocumentForm.addEventListener('submit', handleEditDocumentSubmission);
    
    // Handle cancel button
    if (cancelEditBtn) {
        cancelEditBtn.addEventListener('click', () => {
            const editModal = document.getElementById('editDocumentModal');
            if (editModal) {
                closeModal(editModal);
            }
        });
    }
}

async function loadDocumentTypes() {
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
        if (window.showNotification) {
            window.showNotification('Ошибка загрузки типов документов: ' + error.message, 'error');
        }
    }
}

// Load available services for documents
async function loadAvailableServices() {
    console.log('Starting to load available services...');
    const multiselectContainer = document.getElementById('allowedServicesMultiselect');
    
    if (!multiselectContainer) {
        console.error('Services multiselect container not found');
        return;
    }
    
    // Initialize multiselect if not already done
    if (!multiselectContainer.multiselectInstance) {
        multiselectContainer.multiselectInstance = new CustomMultiselect(multiselectContainer, {
            placeholder: 'Выберите сервисы...',
            selectAllText: 'Выбрать все сервисы',
            noOptionsText: 'Нет доступных сервисов',
            loadingText: 'Загрузка сервисов...'
        });
    }
    
    const multiselect = multiselectContainer.multiselectInstance;
    multiselect.setLoading(true);
    
    try {
        console.log('Sending request to /available-services...');
        const response = await fetch('/available-services');
        console.log('Response status:', response.status);
        console.log('Response OK:', response.ok);
        
        if (!response.ok) {
            throw new Error(`Failed to load services: ${response.status} ${response.statusText}`);
        }
        
        const services = await response.json();
        console.log('Services received:', services);
        
        // Convert services to multiselect format
        const options = services.map(service => ({
            value: service.key,
            label: `${service.name} - ${service.description}`
        }));
        
        multiselect.setLoading(false);
        multiselect.setOptions(options);
        
        // For new documents, select all services by default (first time adding this document type)
        // This will be handled in document type change handler
        
        console.log('Services loaded successfully');
        
    } catch (error) {
        console.error('Error loading services:', error);
        console.error('Error details:', error.message);
        multiselect.setLoading(false);
        multiselect.setError('Ошибка загрузки сервисов: ' + error.message);
        if (window.showNotification) {
            window.showNotification('Ошибка загрузки сервисов: ' + error.message, 'error');
        }
    }
}

async function loadAvailableServicesForEdit(multiselectContainer, selectedServices = []) {
    console.log('Starting to load available services for edit modal...');
    
    if (!multiselectContainer) {
        console.error('Services multiselect container not found');
        return;
    }
    
    // Initialize multiselect if not already done
    if (!multiselectContainer.multiselectInstance) {
        multiselectContainer.multiselectInstance = new CustomMultiselect(multiselectContainer, {
            placeholder: 'Выберите сервисы...',
            selectAllText: 'Выбрать все сервисы',
            noOptionsText: 'Нет доступных сервисов',
            loadingText: 'Загрузка сервисов...'
        });
    }
    
    const multiselect = multiselectContainer.multiselectInstance;
    multiselect.setLoading(true);
    
    try {
        console.log('Sending request to /available-services...');
        const response = await fetch('/available-services');
        console.log('Response status:', response.status);
        console.log('Response OK:', response.ok);
        
        if (!response.ok) {
            throw new Error(`Failed to load services: ${response.status} ${response.statusText}`);
        }
        
        const services = await response.json();
        console.log('Services received:', services);
        console.log('Selected services:', selectedServices);
        
        // Convert services to multiselect format
        const options = services.map(service => ({
            value: service.key,
            label: `${service.name} - ${service.description}`
        }));
        
        multiselect.setLoading(false);
        multiselect.setOptions(options);
        
        // Set selected services
        if (selectedServices && selectedServices.length > 0) {
            multiselect.setSelectedValues(selectedServices);
        }
        
        console.log('Services loaded successfully for edit modal');
        
    } catch (error) {
        console.error('Error loading services for edit:', error);
        console.error('Error details:', error.message);
        multiselect.setLoading(false);
        multiselect.setError('Ошибка загрузки сервисов: ' + error.message);
        if (window.showNotification) {
            window.showNotification('Ошибка загрузки сервисов: ' + error.message, 'error');
        }
    }
}

function handleDocumentTypeChange(event) {
    const selectedOption = event.target.selectedOptions[0];
    const documentFields = document.getElementById('documentFields');
    const filesArea = document.getElementById('newDocumentFilesArea');
    const fileInput = document.getElementById('documentFile');
    
    // Clear existing fields
    documentFields.innerHTML = '';
    
    if (!selectedOption.value || !selectedOption.dataset.documentType) {
        // Disable files area when no document type selected
        if (filesArea) {
            filesArea.style.opacity = '0.5';
            filesArea.style.pointerEvents = 'none';
            filesArea.classList.add('disabled');
        }
        if (fileInput) {
            fileInput.disabled = true;
        }
        return;
    }
    
    // Enable files area when document type is selected
    if (filesArea) {
        filesArea.style.opacity = '1';
        filesArea.style.pointerEvents = 'auto';
        filesArea.classList.remove('disabled');
    }
    if (fileInput) {
        fileInput.disabled = false;
    }
    
    try {
        const documentType = JSON.parse(selectedOption.dataset.documentType);
        
        // Generate form fields based on document type
        if (documentType.fields && documentType.fields.length > 0) {
            documentType.fields.forEach(field => {
                const fieldElement = createFormField(field);
                documentFields.appendChild(fieldElement);
            });
        }
        
        // Check if this is the first document of this type and auto-select all services
        checkAndAutoSelectServicesForNewDocumentType(selectedOption.value);
        
    } catch (error) {
        console.error('Error parsing document type:', error);
    }
}

function createFormField(field) {
    const fieldDiv = document.createElement('div');
    fieldDiv.className = 'form-group';
    
    const label = document.createElement('label');
    label.setAttribute('for', `field_${field.id}`);
    label.textContent = field.label;
    
    let input;
    
    switch (field.type) {
        case 'text':
        case 'email':
        case 'tel':
        case 'url':
            input = document.createElement('input');
            input.type = field.type;
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.placeholder) input.placeholder = field.placeholder;
            if (field.required) input.required = true;
            if (field.maxlength) input.maxLength = field.maxlength;
            
            // Apply formatting if available
            if (field.format) {
                applyFieldFormatting(input, field.format);
            } else {
                // Apply basic validation for fields without formatting
                applyBasicValidation(input);
            }
            break;
            
        case 'textarea':
            input = document.createElement('textarea');
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.placeholder) input.placeholder = field.placeholder;
            if (field.required) input.required = true;
            break;
            
        case 'select':
            input = document.createElement('select');
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.required) input.required = true;
            
            // Add empty option
            const emptyOption = document.createElement('option');
            emptyOption.value = '';
            emptyOption.textContent = 'Выберите...';
            input.appendChild(emptyOption);
            
            // Add options
            if (field.options) {
                field.options.forEach(option => {
                    const optionElement = document.createElement('option');
                    optionElement.value = option.value;
                    optionElement.textContent = option.label;
                    input.appendChild(optionElement);
                });
            }
            applyBasicValidation(input);
            break;
            
        case 'date':
            input = document.createElement('input');
            input.type = 'date';
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.required) input.required = true;
            applyBasicValidation(input);
            break;
            
        case 'number':
            input = document.createElement('input');
            input.type = 'number';
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.placeholder) input.placeholder = field.placeholder;
            if (field.required) input.required = true;
            if (field.min !== undefined) input.min = field.min;
            if (field.max !== undefined) input.max = field.max;
            applyBasicValidation(input);
            break;
            
        case 'textarea':
            input = document.createElement('textarea');
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.placeholder) input.placeholder = field.placeholder;
            if (field.required) input.required = true;
            applyBasicValidation(input);
            break;
            
        default:
            input = document.createElement('input');
            input.type = 'text';
            input.id = `field_${field.id}`;
            input.name = `field_${field.id}`;
            if (field.placeholder) input.placeholder = field.placeholder;
            if (field.required) input.required = true;
            applyBasicValidation(input);
    }
    
    fieldDiv.appendChild(label);
    fieldDiv.appendChild(input);
    
    // // Add field hint if format mask is available
    // if (field.format && field.format.mask) {
    //     const hint = document.createElement('small');
    //     hint.className = 'field-hint';
    //     hint.textContent = `Формат: ${field.format.mask.replace(/9/g, '#').replace(/A/g, 'А')}`;
    //     fieldDiv.appendChild(hint);
        
    //     // Add data attribute for CSS styling
    //     input.setAttribute('data-mask', field.format.mask);
    // }
    
    // Add error message container for format errors
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error';
    errorDiv.textContent = 'Неверный формат данных';
    fieldDiv.appendChild(errorDiv);
    
    // Add required error message container
    const requiredErrorDiv = document.createElement('div');
    requiredErrorDiv.className = 'field-required-error';
    requiredErrorDiv.textContent = 'Обязательно к заполнению';
    fieldDiv.appendChild(requiredErrorDiv);
    
    // Add format hint container for invalid format
    if (field.format && field.format.mask) {
        const formatHintDiv = document.createElement('div');
        formatHintDiv.className = 'field-format-hint';
        formatHintDiv.textContent = `Требуемый формат: ${field.format.mask.replace(/9/g, '#').replace(/A/g, 'А')}`;
        fieldDiv.appendChild(formatHintDiv);
    }
    
    // Применяем начальную валидацию для пустых обязательных полей
    if (field.required && (!input.value || input.value.trim() === '')) {
        // Используем setTimeout чтобы дать DOM время обновиться
        setTimeout(() => {
            validateFieldState(input, input.value, field.format);
        }, 0);
    }
    
    return fieldDiv;
}

// Check if this is the first document of this type and auto-select all services
async function checkAndAutoSelectServicesForNewDocumentType(documentType) {
    console.log('Checking if document type is new:', documentType);
    
    try {
        // Get existing user documents to check if this document type already exists
        const response = await fetch('/profile/documents');
        if (!response.ok) {
            console.error('Failed to fetch existing documents');
            return;
        }
        
        const documents = await response.json();
        console.log('Existing documents:', documents);
        
        // Check if there are any existing documents of this type
        const existingDocumentsOfType = documents.filter(doc => doc.document_type === documentType);
        console.log('Existing documents of type', documentType, ':', existingDocumentsOfType);
        
        // If this is the first document of this type, auto-select all services
        if (existingDocumentsOfType.length === 0) {
            console.log('This is the first document of type', documentType, ', auto-selecting all services');
            
            const multiselectContainer = document.getElementById('allowedServicesMultiselect');
            if (multiselectContainer && multiselectContainer.multiselectInstance) {
                const multiselect = multiselectContainer.multiselectInstance;
                
                // Wait a bit for services to load if they haven't loaded yet
                if (multiselect.availableOptions.length === 0) {
                    // Wait for services to load
                    let attempts = 0;
                    const checkLoaded = setInterval(() => {
                        attempts++;
                        if (multiselect.availableOptions.length > 0 || attempts > 50) { // Max 5 seconds
                            clearInterval(checkLoaded);
                            if (multiselect.availableOptions.length > 0) {
                                multiselect.selectAll();
                                console.log('Auto-selected all services for new document type');
                            }
                        }
                    }, 100);
                } else {
                    multiselect.selectAll();
                    console.log('Auto-selected all services for new document type');
                }
            }
        } else {
            console.log('Document type', documentType, 'already exists, not auto-selecting services');
        }
        
    } catch (error) {
        console.error('Error checking document type:', error);
    }
}

// Apply field formatting based on format configuration
function applyFieldFormatting(input, format) {
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
            validateFieldState(input, formatted, format);
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
    
    // Отключаем встроенную HTML5 валидацию браузера
    // Pattern храним только в JavaScript для нашей собственной валидации
    // НЕ устанавливаем pattern атрибут чтобы избежать конфликта с HTML5 валидацией
    
    // Добавляем обработчики для валидации
    input.addEventListener('input', function(e) {
        // Проверяем, что мы в модальном окне
        if (e.target.closest('.modal-form')) {
            validateFieldState(e.target, e.target.value, format);
        }
    });
    
    input.addEventListener('blur', function(e) {
        // Проверяем, что мы в модальном окне
        if (e.target.closest('.modal-form')) {
            validateFieldState(e.target, e.target.value, format);
        }
    });
    
    input.addEventListener('focus', function(e) {
        const formGroup = e.target.closest('.form-group');
        const modalForm = e.target.closest('.modal-form');
        if (formGroup && modalForm) {
            formGroup.classList.remove('has-error', 'show-format-hint', 'show-required-error');
            // Очищаем встроенную валидацию браузера
            e.target.setCustomValidity('');
        }
    });
}

// Функция базовой валидации для полей без форматирования
function applyBasicValidation(input) {
    input.addEventListener('input', function(e) {
        // Проверяем, что мы в модальном окне
        if (e.target.closest('.modal-form')) {
            validateFieldState(e.target, e.target.value, null);
        }
    });
    
    input.addEventListener('blur', function(e) {
        // Проверяем, что мы в модальном окне
        if (e.target.closest('.modal-form')) {
            validateFieldState(e.target, e.target.value, null);
        }
    });
    
    input.addEventListener('focus', function(e) {
        const formGroup = e.target.closest('.form-group');
        const modalForm = e.target.closest('.modal-form');
        if (formGroup && modalForm) {
            formGroup.classList.remove('has-error', 'show-format-hint', 'show-required-error');
            // Очищаем встроенную валидацию браузера
            e.target.setCustomValidity('');
        }
    });
}

// Функция валидации состояния поля (только для модального окна документов)
function validateFieldState(input, value, format) {
    const formGroup = input.closest('.form-group');
    if (!formGroup) return;
    
    // Проверяем, находится ли поле в модальном окне документов
    const modalForm = input.closest('.modal-form');
    if (!modalForm) return; // Не применяем валидацию если не в модальном окне
    
    // Убираем все классы состояний
    formGroup.classList.remove('has-error', 'has-success', 'show-format-hint', 'show-required-error', 'from-database');
    
    // Проверяем, является ли поле пустым
    const isEmpty = !value || value.trim() === '';
    
    // Проверяем, заполнено ли поле из БД (можно определить по data-атрибуту)
    const isFromDatabase = input.hasAttribute('data-from-db');
    
    if (isFromDatabase) {
        // Поле заполнено из БД - нейтральный стиль
        formGroup.classList.add('from-database');
        input.setCustomValidity('');
        return;
    }
    
    if (isEmpty) {
        // Пустое обязательное поле - красная граница + сообщение "обязательно к заполнению"
        if (input.required) {
            formGroup.classList.add('has-error', 'show-required-error');
            input.setCustomValidity('Обязательно к заполнению');
        }
        return;
    }
    
    // Проверяем формат если есть паттерн
    if (format && format.pattern) {
        const cleanValue = value.replace(/[^\w]/g, '');
        const regex = new RegExp(format.pattern);
        
        if (regex.test(cleanValue)) {
            // Формат правильный - зеленая граница
            formGroup.classList.add('has-success');
            input.setCustomValidity('');
        } else {
            // Формат неправильный - красная граница + показываем только подсказку формата
            formGroup.classList.add('has-error', 'show-format-hint');
            input.setCustomValidity('Неверный формат данных');
        }
    } else {
        // Нет паттерна, но поле не пустое - зеленая граница
        formGroup.classList.add('has-success');
        input.setCustomValidity('');
    }
}

// Функция для установки значений полей из базы данных
function setFieldValueFromDatabase(fieldId, value) {
    const input = document.getElementById(`field_${fieldId}`);
    if (input) {
        input.value = value;
        input.setAttribute('data-from-db', 'true');
        const formGroup = input.closest('.form-group');
        if (formGroup) {
            formGroup.classList.add('from-database');
        }
    }
}

async function handleDocumentSubmission(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    
    // Show loading state
    submitButton.disabled = true;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Сохранение...';
    
    try {
        // Get document type
        const documentTypeSelect = document.getElementById('documentTypeSelect');
        const selectedDocumentType = documentTypeSelect.value;
        
        if (!selectedDocumentType) {
            throw new Error('Выберите тип документа');
        }
        
        // Collect form fields
        const fields = {};
        const fieldInputs = form.querySelectorAll('[name^="field_"]');
        fieldInputs.forEach(input => {
            const fieldId = input.name.replace('field_', '');
            fields[fieldId] = input.value;
        });
        
        // Collect selected services
        const allowedServicesContainer = document.getElementById('allowedServicesMultiselect');
        let allowedServices = [];
        if (allowedServicesContainer && allowedServicesContainer.multiselectInstance) {
            allowedServices = allowedServicesContainer.multiselectInstance.getSelectedValues();
        }
        
        // Validate services selection
        if (allowedServices.length === 0) {
            throw new Error('Выберите хотя бы один сервис для использования документа');
        }
        
        // Create document title based on type
        const selectedOption = documentTypeSelect.selectedOptions[0];
        const documentTypeName = selectedOption ? selectedOption.textContent : selectedDocumentType;
        
        const requestData = {
            document_type: selectedDocumentType,
            title: documentTypeName,
            fields: fields,
            allowed_services: allowedServices
        };
        
        console.log('Sending document data:', requestData);
        
        // First create the document
        const response = await fetch('/profile/documents', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            const documentId = result.document_id;
            
            // Upload files if any (from unified area)
            const newFiles = Array.from(document.querySelectorAll('#newDocumentFilesArea .file-item[data-status="new"]'));
            if (newFiles.length > 0) {
                const filesToUpload = newFiles.map(item => item.fileObject).filter(file => file);
                if (filesToUpload.length > 0) {
                    await uploadDocumentFiles(documentId, filesToUpload);
                }
            }
            
            if (window.showNotification) {
                window.showNotification(result.message || 'Документ успешно добавлен', 'success');
            }
            
            // Close modal and reset form
            const modal = document.getElementById('documentModal');
            closeModal(modal);
            form.reset();
            document.getElementById('documentFields').innerHTML = '';
            
            // Clear services selection
            const allowedServicesSelect = document.getElementById('allowedServicesSelect');
            if (allowedServicesSelect) {
                Array.from(allowedServicesSelect.options).forEach(option => {
                    option.selected = false;
                });
            }
            
            // Clear unified files area
            const newFilesArea = document.getElementById('newDocumentFilesArea');
            if (newFilesArea) {
                updateUnifiedFilesArea(newFilesArea, []);
            }
            
            // Reload documents list
            loadUserDocuments();
            
        } else {
            throw new Error(result.error || 'Ошибка при добавлении документа');
        }
        
    } catch (error) {
        console.error('Error submitting document:', error);
        if (window.showNotification) {
            window.showNotification(error.message || 'Ошибка при добавлении документа', 'error');
        }
    } finally {
        // Restore button state
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

// Handle edit document form submission
async function handleEditDocumentSubmission(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    
    try {
        // Show loading state
        submitButton.disabled = true;
        submitButton.textContent = 'Сохранение...';
        
        // Get document ID
        const documentId = form.querySelector('#editDocumentId').value;
        if (!documentId) {
            throw new Error('ID документа не найден');
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
            
            // Validate field using existing validation function
            const fieldContainer = input.closest('.form-group');
            
            // Check if field has validation errors after calling validateFieldState
            validateFieldState(input, value, null);
            
            // Check if validation failed (has error class)
            if (fieldContainer?.classList.contains('has-error')) {
                hasErrors = true;
                return;
            }
            
            input.classList.remove('field-error-state');
            formData[fieldId] = value;
        });
        
        // Collect selected services
        const allowedServicesContainer = form.querySelector('#editAllowedServicesMultiselect');
        let allowedServices = [];
        if (allowedServicesContainer && allowedServicesContainer.multiselectInstance) {
            allowedServices = allowedServicesContainer.multiselectInstance.getSelectedValues();
            console.log('Selected services from multiselect:', allowedServices);
        } else {
            console.log('Multiselect container or instance not found');
        }
        
        if (hasErrors) {
            throw new Error('Пожалуйста, исправьте ошибки в форме');
        }
        
        // Prepare update data
        const updateData = { 
            fields: formData,
            allowed_services: allowedServices
        };
        
        console.log('Sending update data:', updateData);
        
        // Send update request
        const response = await fetch(`/profile/documents/${documentId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(updateData)
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || `Ошибка сервера: ${response.status}`);
        }
        
        // Upload new files if any (from unified area)
        const newFiles = Array.from(document.querySelectorAll('.file-item[data-status="new"]'));
        if (newFiles.length > 0) {
            const filesToUpload = newFiles.map(item => item.fileObject).filter(file => file);
            if (filesToUpload.length > 0) {
                await uploadDocumentFiles(documentId, filesToUpload);
            }
        }
        
        // Success
        showNotification('Документ успешно обновлен', 'success');
        
        // Close modal
        const editModal = document.getElementById('editDocumentModal');
        if (editModal) {
            closeModal(editModal);
        }
        
        // Reload documents list
        setTimeout(loadUserDocuments, 100);
        
    } catch (error) {
        console.error('Error updating document:', error);
        showNotification(error.message || 'Ошибка при обновлении документа', 'error');
        
    } finally {
        // Restore button state
        submitButton.disabled = false;
        submitButton.textContent = originalText;
    }
}

// Function to upload files to a document
async function uploadDocumentFiles(documentId, files) {
    if (!files || files.length === 0) {
        return;
    }
    
    try {
        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch(`/profile/documents/${documentId}/attachments`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                console.error(`Failed to upload ${file.name}: ${response.status}`);
                showNotification(`Ошибка загрузки файла ${file.name}`, 'error');
            }
        }
    } catch (error) {
        console.error('Error uploading files:', error);
        showNotification('Ошибка загрузки файлов', 'error');
    }
}

// Function to load document types for edit modal
async function loadDocumentTypesForEdit(selectElement, selectedType) {
    try {
        const response = await fetch('/document-types');
        if (!response.ok) {
            throw new Error(`Failed to load document types: ${response.status}`);
        }
        
        const documentTypes = await response.json();
        
        // Clear existing options
        selectElement.innerHTML = '<option value="">Выберите тип документа</option>';
        
        // Add document types and select the current one
        documentTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type.id;
            option.textContent = type.name;
            option.dataset.documentType = JSON.stringify(type);
            
            if (type.id === selectedType) {
                option.selected = true;
            }
            
            selectElement.appendChild(option);
        });
        
    } catch (error) {
        console.error('Error loading document types for edit:', error);
        throw error;
    }
}

// Function to load document fields for edit modal with existing data
async function loadDocumentFieldsForEdit(fieldsContainer, documentType, existingData) {
    try {
        // Find the document type data
        const response = await fetch('/document-types');
        if (!response.ok) {
            throw new Error(`Failed to load document types: ${response.status}`);
        }
        
        const documentTypes = await response.json();
        const typeData = documentTypes.find(type => type.id === documentType);
        
        if (!typeData || !typeData.fields) {
            fieldsContainer.innerHTML = '<p>Поля для данного типа документа не найдены</p>';
            return;
        }
        
        // Clear existing fields
        fieldsContainer.innerHTML = '';
        
        // Generate form fields and populate with existing data
        console.log('Document type fields:', typeData.fields);
        console.log('Existing data:', existingData);
        
        typeData.fields.forEach(field => {
            const fieldElement = createFormField(field);
            
            // Populate field with existing data
            const input = fieldElement.querySelector(`#field_${field.id}`);
            console.log(`Looking for field ${field.id}, input found:`, !!input, 'data:', existingData[field.id]);
            
            if (input && existingData[field.id]) {
                input.value = existingData[field.id];
                console.log(`Set value for field ${field.id}:`, existingData[field.id]);
                
                // Trigger validation for populated field
                setTimeout(() => {
                    validateFieldState(input, input.value, field.format);
                }, 0);
            }
            
            fieldsContainer.appendChild(fieldElement);
        });
        
    } catch (error) {
        console.error('Error loading document fields for edit:', error);
        fieldsContainer.innerHTML = '<p>Ошибка загрузки полей документа</p>';
    }
}

// Function to load and display user documents
async function loadUserDocuments() {
    const documentsGrid = document.getElementById('documentsGrid');
    if (!documentsGrid) {
        console.error('Documents grid container not found');
        return;
    }
    
    try {
        const response = await fetch('/profile/documents');
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
            const docCard = await createDocumentCardWithAttachments(doc);
            documentsGrid.appendChild(docCard);
        }
        
    } catch (error) {
        console.error('Error loading documents:', error);
        documentsGrid.innerHTML = '<p class="error-message">Ошибка загрузки документов</p>';
    }
}

// Function to create a document card element with attachments
async function createDocumentCardWithAttachments(doc) {
    const card = document.createElement('div');
    card.className = 'document-card';
    
    // Get attachments for this document
    let attachments = [];
    let attachmentsHtml = '';
    let downloadButtonHtml = '';
    
    try {
        const response = await fetch(`/profile/documents/${doc.id}/attachments`);
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
                    <button class="btn btn-info btn-download-attachments" data-doc-id="${doc.id}" title="Скачать вложения">
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

    // Create services HTML
    let servicesHtml = '';
    if (doc.allowed_services && doc.allowed_services.length > 0) {
        const serviceNames = {
            'referal': 'Реферальная программа',
            'calculators': 'Калькуляторы',
            'client-service': 'Клиентский сервис'
        };
        
        const serviceLabels = doc.allowed_services.map(serviceKey => 
            serviceNames[serviceKey] || serviceKey
        ).join(', ');
        
        servicesHtml = `<p><strong>Используется в сервисах:</strong> ${serviceLabels}</p>`;
    } else {
        servicesHtml = '<p><strong>Используется в сервисах:</strong> <span class="warning-text">не настроено</span></p>';
    }

    card.innerHTML = `
        <div class="document-info">
            <h4>${doc.title || doc.document_type}</h4>
            <p>Тип: ${doc.document_type}</p>
            <p>Добавлен: ${new Date(doc.created_at).toLocaleDateString('ru-RU')}</p>
            ${servicesHtml}
            ${fieldsHtml}
        </div>
        <div class="document-bottom-row">
            ${attachmentsHtml}
            <div class="document-actions">
                ${downloadButtonHtml}
                <button class="btn btn-secondary btn-edit-doc" data-doc-id="${doc.id}">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-danger btn-delete-doc" data-doc-id="${doc.id}">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>`;

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
    
    return card;
}

// Function to create a document card element (legacy - keeping for compatibility)
function createDocumentCard(doc) {
    const card = document.createElement('div');
    card.className = 'document-card';
    
    // Format allowed services for display
    let servicesDisplay = '';
    if (doc.allowed_services && doc.allowed_services.length > 0) {
        servicesDisplay = `<p>Сервисы: ${doc.allowed_services.join(', ')}</p>`;
    }
    
    card.innerHTML = `
        <div class="document-info">
            <h4>${doc.title || doc.document_type}</h4>
            <p>Тип: ${doc.document_type}</p>
            <p>Добавлен: ${new Date(doc.created_at).toLocaleDateString('ru-RU')}</p>
            ${servicesDisplay}
        </div>
        <div class="document-actions">
            <button class="btn btn-secondary btn-edit-doc" data-doc-id="${doc.id}">
                <i class="fas fa-edit"></i>
            </button>
            <button class="btn btn-danger btn-delete-doc" data-doc-id="${doc.id}">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;
    return card;
}

// Load documents when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Load documents when documents tab is first accessed
    const documentsTab = document.querySelector('[data-tab="documents"]');
    if (documentsTab) {
        documentsTab.addEventListener('click', function() {
            // Small delay to ensure tab content is visible
            setTimeout(loadUserDocuments, 100);
        }, { once: true }); // Load only once
    }
    
    // Initialize bulk actions handlers
    initializeBulkActions();
});

// Bulk Actions Functions
function initializeBulkActions() {
    const selectAllCheckbox = document.getElementById('selectAllFiles');
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const filesContainer = document.getElementById('editFilesContainer');
            if (filesContainer) {
                const fileCheckboxes = filesContainer.querySelectorAll('.file-checkbox');
                fileCheckboxes.forEach(checkbox => {
                    checkbox.checked = selectAllCheckbox.checked;
                });
                updateBulkActionsState();
            }
        });
    }
    
    if (bulkDeleteBtn) {
        bulkDeleteBtn.addEventListener('click', handleBulkDelete);
    }
}

function updateBulkActionsState() {
    const filesContainer = document.getElementById('editFilesContainer');
    const bulkActionsPanel = document.getElementById('bulkActionsPanel');
    const selectedCountElement = document.getElementById('selectedCount');
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    const selectAllCheckbox = document.getElementById('selectAllFiles');
    
    if (!filesContainer || !bulkActionsPanel) return;
    
    const allCheckboxes = filesContainer.querySelectorAll('.file-checkbox');
    const checkedCheckboxes = filesContainer.querySelectorAll('.file-checkbox:checked');
    const hasFiles = allCheckboxes.length > 0;
    const hasCheckedFiles = checkedCheckboxes.length > 0;
    
    // Show/hide bulk actions panel based on file presence
    bulkActionsPanel.style.display = hasFiles ? 'flex' : 'none';
    
    if (hasFiles) {
        // Update selected count
        if (selectedCountElement) {
            selectedCountElement.textContent = `${checkedCheckboxes.length} выбрано`;
        }
        
        // Update bulk delete button state
        if (bulkDeleteBtn) {
            bulkDeleteBtn.disabled = !hasCheckedFiles;
        }
        
        // Update select all checkbox state
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = checkedCheckboxes.length === allCheckboxes.length;
            selectAllCheckbox.indeterminate = hasCheckedFiles && checkedCheckboxes.length < allCheckboxes.length;
        }
    }
    
    // Add event listeners to file checkboxes
    allCheckboxes.forEach(checkbox => {
        checkbox.removeEventListener('change', updateBulkActionsState); // Remove old listeners
        checkbox.addEventListener('change', updateBulkActionsState);
    });
}

async function handleBulkDelete() {
    const filesContainer = document.getElementById('editFilesContainer');
    if (!filesContainer) return;
    
    const checkedCheckboxes = filesContainer.querySelectorAll('.file-checkbox:checked');
    if (checkedCheckboxes.length === 0) return;
    
    // Show confirmation dialog
    const fileNames = Array.from(checkedCheckboxes).map(cb => {
        const fileItem = cb.closest('.file-item');
        return fileItem ? fileItem.querySelector('.file-item-info').textContent.trim() : '';
    }).filter(name => name);
    
    const confirmMessage = checkedCheckboxes.length === 1 
        ? `Удалить файл "${fileNames[0]}"?`
        : `Удалить ${checkedCheckboxes.length} файлов?\n\n${fileNames.slice(0, 5).join('\n')}${fileNames.length > 5 ? '\n...' : ''}`;
    
    if (!confirm(confirmMessage)) {
        return;
    }
    
    const docId = getCurrentEditingDocumentId();
    if (!docId) return;
    
    // Disable bulk delete button during operation
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    if (bulkDeleteBtn) {
        bulkDeleteBtn.disabled = true;
        bulkDeleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Удаление...';
    }
    
    // Delete files one by one
    let successCount = 0;
    let errorCount = 0;
    
    for (const checkbox of checkedCheckboxes) {
        const fileItem = checkbox.closest('.file-item');
        if (!fileItem) continue;
        
        const fileId = fileItem.dataset.fileId;
        const status = fileItem.dataset.status;
        
        try {
            if (status === 'uploaded') {
                // For uploaded files, call API
                const success = await removeAttachment(docId, fileId, true); // true = skip confirmation
                if (success) {
                    successCount++;
                } else {
                    errorCount++;
                }
            } else {
                // For new files, just remove from DOM
                fileItem.remove();
                successCount++;
            }
        } catch (error) {
            console.error('Error deleting file:', error);
            errorCount++;
        }
    }
    
    // Show result notification
    if (successCount > 0) {
        showNotification(`Удалено файлов: ${successCount}`, 'success');
    }
    if (errorCount > 0) {
        showNotification(`Ошибок при удалении: ${errorCount}`, 'error');
    }
    
    // Update bulk actions state
    updateBulkActionsState();
    
    // Re-enable bulk delete button
    if (bulkDeleteBtn) {
        bulkDeleteBtn.disabled = false;
        bulkDeleteBtn.innerHTML = '<i class="fas fa-trash"></i> Удалить выбранные';
    }
    
    // Update unified area visibility
    const areaContainer = document.getElementById('editDocumentFilesArea');
    if (areaContainer) {
        updateUnifiedAreaVisibility(areaContainer);
    }
}

// Password Security Tab Functions
document.addEventListener('DOMContentLoaded', function() {
    initPasswordValidation();
    initPasswordToggleButtons();
});

function initPasswordValidation() {
    const newPasswordInput = document.getElementById('newPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    
    if (!newPasswordInput || !confirmPasswordInput) return;
    
    function validatePasswords() {
        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        const newPasswordGroup = newPasswordInput.closest('.form-group');
        const confirmPasswordGroup = confirmPasswordInput.closest('.form-group');
        
        // Clear previous validation states
        [newPasswordGroup, confirmPasswordGroup].forEach(group => {
            if (group) {
                group.classList.remove('has-error', 'has-success');
            }
        });
        
        // Only validate if both fields have content
        if (newPassword && confirmPassword) {
            if (newPassword === confirmPassword) {
                // Passwords match - show success
                if (newPasswordGroup) newPasswordGroup.classList.add('has-success');
                if (confirmPasswordGroup) confirmPasswordGroup.classList.add('has-success');
            } else {
                // Passwords don't match - show error
                if (newPasswordGroup) newPasswordGroup.classList.add('has-error');
                if (confirmPasswordGroup) confirmPasswordGroup.classList.add('has-error');
            }
        } else if (newPassword || confirmPassword) {
            // One field is empty, the other is not - show error
            if (newPassword && !confirmPassword && confirmPasswordGroup) {
                confirmPasswordGroup.classList.add('has-error');
            } else if (!newPassword && confirmPassword && newPasswordGroup) {
                newPasswordGroup.classList.add('has-error');
            }
        }
    }
    
    // Add event listeners for real-time validation
    newPasswordInput.addEventListener('input', validatePasswords);
    confirmPasswordInput.addEventListener('input', validatePasswords);
    newPasswordInput.addEventListener('blur', validatePasswords);
    confirmPasswordInput.addEventListener('blur', validatePasswords);
}

function initPasswordToggleButtons() {
    const toggleButtons = document.querySelectorAll('.password-toggle-btn');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const input = this.previousElementSibling;
            if (!input) return;
            
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            
            // Update icon
            const icon = this.querySelector('i');
            if (icon) {
                icon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
            }
            
            // Update tooltip
            this.setAttribute('data-tooltip', isPassword ? 'Спрятать пароль' : 'Показать пароль');
            
            // Update aria-label for accessibility
            this.setAttribute('aria-label', isPassword ? 'Скрыть пароль' : 'Показать пароль');
        });
    });
}

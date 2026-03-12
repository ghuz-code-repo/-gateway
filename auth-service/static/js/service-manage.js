// Service Management JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Tab switching functionality
    initializeTabs();
    
    // Modal functionality
    initializeModals();
    
    // Form handlers
    initializeFormHandlers();
});

function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetTab = this.getAttribute('data-tab');
            
            // Remove active class from all tabs and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            this.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });
}

function initializeModals() {
    // Role modal
    const addRoleBtn = document.getElementById('add-role-btn');
    const roleModal = document.getElementById('role-modal');
    const editRoleBtns = document.querySelectorAll('.edit-role-btn');
    
    if (addRoleBtn) {
        addRoleBtn.addEventListener('click', function() {
            openRoleModal();
        });
    }
    
    editRoleBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const roleId = this.getAttribute('data-role-id');
            const roleName = this.getAttribute('data-role-name');
            const roleDescription = this.getAttribute('data-role-description');
            const rolePermissions = this.getAttribute('data-role-permissions').split(',');
            
            openRoleModal(roleId, roleName, roleDescription, rolePermissions);
        });
    });
    
    // Permission modal
    const addPermissionBtn = document.getElementById('add-permission-btn');
    const editPermissionBtns = document.querySelectorAll('.edit-permission-btn');
    
    if (addPermissionBtn) {
        addPermissionBtn.addEventListener('click', function() {
            openPermissionModal();
        });
    }
    
    editPermissionBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const permName = this.getAttribute('data-perm-name');
            const permDisplay = this.getAttribute('data-perm-display');
            const permDescription = this.getAttribute('data-perm-description');
            
            openPermissionModal(permName, permDisplay, permDescription);
        });
    });
    
    // Assign user modal
    const assignUserBtn = document.getElementById('assign-user-btn');
    if (assignUserBtn) {
        assignUserBtn.addEventListener('click', function() {
            openModal('assign-user-modal');
        });
    }
    
    // Close modals
    const closeButtons = document.querySelectorAll('.modal .close');
    closeButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const modal = this.closest('.modal');
            closeModal(modal.id);
        });
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            closeModal(event.target.id);
        }
    });
}

function openRoleModal(roleId = null, name = '', description = '', permissions = []) {
    const modal = document.getElementById('role-modal');
    const form = document.getElementById('role-form');
    const title = document.getElementById('role-modal-title');
    const nameInput = document.getElementById('role-name');
    const descriptionInput = document.getElementById('role-description');
    const permissionCheckboxes = document.querySelectorAll('input[name="permissions"]');
    
    // Set form action and title
    if (roleId) {
        title.textContent = 'Редактировать роль';
        form.action = `/admin/services/${getServiceId()}/roles/${roleId}`;
    } else {
        title.textContent = 'Добавить роль';
        form.action = `/admin/services/${getServiceId()}/roles`;
    }
    
    // Fill form data
    nameInput.value = name;
    descriptionInput.value = description;
    
    // Clear and set permissions
    permissionCheckboxes.forEach(checkbox => {
        checkbox.checked = permissions.includes(checkbox.value);
    });
    
    openModal('role-modal');
}

function openPermissionModal(name = '', displayName = '', description = '') {
    const modal = document.getElementById('permission-modal');
    const title = document.getElementById('permission-modal-title');
    const nameInput = document.getElementById('perm-name');
    const displayInput = document.getElementById('perm-display');
    const descriptionInput = document.getElementById('perm-description');
    
    if (name) {
        title.textContent = 'Редактировать разрешение';
        nameInput.value = name;
        nameInput.readOnly = true; // Don't allow changing permission name
    } else {
        title.textContent = 'Добавить разрешение';
        nameInput.value = '';
        nameInput.readOnly = false;
    }
    
    displayInput.value = displayName;
    descriptionInput.value = description;
    
    openModal('permission-modal');
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
        // Focus first input
        const firstInput = modal.querySelector('input, textarea, select');
        if (firstInput) {
            firstInput.focus();
        }
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        // Reset form if it exists
        const form = modal.querySelector('form');
        if (form) {
            form.reset();
        }
    }
}

function initializeFormHandlers() {
    // Handle service update form submission
    const serviceForm = document.querySelector('form.form');
    if (serviceForm && !serviceForm.action.includes('/delete')) {
        serviceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            submitServiceForm();
        });
    }
    
    // Handle role form submission
    const roleForm = document.getElementById('role-form');
    if (roleForm) {
        roleForm.addEventListener('submit', function(e) {
            e.preventDefault();
            submitRoleForm();
        });
    }
    
    // Handle permission form submission
    const permissionForm = document.getElementById('permission-form');
    if (permissionForm) {
        permissionForm.addEventListener('submit', function(e) {
            e.preventDefault();
            submitPermissionForm();
        });
    }
    
    // Handle assign user form submission
    const assignUserForm = document.getElementById('assign-user-form');
    if (assignUserForm) {
        assignUserForm.addEventListener('submit', function(e) {
            e.preventDefault();
            submitAssignUserForm();
        });
    }
}

function submitRoleForm() {
    const form = document.getElementById('role-form');
    const formData = new FormData(form);
    
    fetch(form.action, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            showNotification('Роль успешно сохранена', 'success');
            closeModal('role-modal');
            setTimeout(() => window.location.reload(), 1000);
        } else {
            throw new Error('Ошибка сохранения роли');
        }
    })
    .catch(error => {
        showNotification(error.message, 'error');
    });
}

function submitPermissionForm() {
    const form = document.getElementById('permission-form');
    const formData = new FormData(form);
    
    fetch(form.action, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            showNotification('Разрешение успешно сохранено', 'success');
            closeModal('permission-modal');
            setTimeout(() => window.location.reload(), 1000);
        } else {
            throw new Error('Ошибка сохранения разрешения');
        }
    })
    .catch(error => {
        showNotification(error.message, 'error');
    });
}

function submitServiceForm() {
    const form = document.querySelector('form.form');
    const formData = new FormData(form);
    
    fetch(window.location.pathname, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            return response.json().catch(() => ({})); // Handle both JSON and non-JSON responses
        } else if (response.status === 400) {
            return response.json();
        } else {
            throw new Error('Ошибка обновления сервиса');
        }
    })
    .then(data => {
        if (data.requires_confirmation) {
            // Show confirmation dialog for key changes
            if (confirm(`${data.message}\n\nВы уверены, что хотите изменить ключ сервиса? Это может повлиять на интегрированные системы.`)) {
                // Add confirmation flag and resubmit
                formData.append('confirmKeyChange', 'true');
                return fetch(window.location.pathname, {
                    method: 'POST',
                    body: formData
                })
                .then(response => {
                    if (response.ok) {
                        showNotification('Сервис успешно обновлен', 'success');
                        setTimeout(() => window.location.reload(), 1000);
                    } else {
                        return response.json().then(err => {
                            throw new Error(err.error || 'Ошибка обновления сервиса');
                        });
                    }
                });
            }
        } else if (data.error) {
            throw new Error(data.error);
        } else {
            showNotification('Сервис успешно обновлен', 'success');
            setTimeout(() => window.location.reload(), 1000);
        }
    })
    .catch(error => {
        showNotification(error.message, 'error');
    });
}

function submitAssignUserForm() {
    const form = document.getElementById('assign-user-form');
    const formData = new FormData(form);
    
    fetch(form.action, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            showNotification('Пользователь успешно назначен', 'success');
            closeModal('assign-user-modal');
            setTimeout(() => window.location.reload(), 1000);
        } else {
            throw new Error('Ошибка назначения пользователя');
        }
    })
    .catch(error => {
        showNotification(error.message, 'error');
    });
}

function showNotification(message, type) {
    const container = document.getElementById('notifications-container');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">&times;</button>
    `;
    
    container.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

function getServiceId() {
    // Extract service ID from URL
    const path = window.location.pathname;
    const match = path.match(/\/admin\/services\/([^\/]+)\/manage/);
    return match ? match[1] : null;
}

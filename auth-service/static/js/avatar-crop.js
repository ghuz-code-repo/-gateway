class AvatarCrop {
    constructor() {
        console.log('AvatarCrop class initialized');
        this.image = null;
        this.cropBox = null;
        this.cropBoxReady = false;
        this.isExistingAvatar = false;
        this.isDragging = false;
        this.isResizing = false;
        this.startX = 0;
        this.startY = 0;
        this.currentHandle = null;
        this.imageData = null;
        this.modal = document.getElementById('cropModal');
        this.isUploading = false; // Flag to prevent multiple uploads
        
        this.initEventListeners();
    }
    
    initEventListeners() {
        console.log('Initializing event listeners');
        
        // Avatar click to open modal
        const avatarContainer = document.getElementById('avatarContainer');
        const avatarInput = document.getElementById('avatarInput');
        
        console.log('Avatar container:', avatarContainer);
        console.log('Avatar input:', avatarInput);
        
        if (avatarContainer && avatarInput) {
            // Удаляем все предыдущие обработчики, если они есть
            avatarContainer.replaceWith(avatarContainer.cloneNode(true));
            const newAvatarContainer = document.getElementById('avatarContainer');
            
            newAvatarContainer.addEventListener('click', (e) => {
                console.log('Avatar container clicked - checking conditions');
                
                // Не открывать модальное окно, если оно уже открыто
                if (this.modal && this.modal.style.display === 'block') {
                    console.log('Modal already open, ignoring click');
                    return;
                }
                
                // Останавливаем все события
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                
                console.log('Opening modal...');
                this.openModal();
            }, { once: false }); // Используем capture phase
            
            avatarInput.addEventListener('change', (e) => {
                console.log('Avatar input changed:', e.target.files[0]);
                e.stopPropagation(); // Предотвращаем всплытие
                
                // Prevent processing if already uploading
                if (this.isUploading) {
                    console.log('Upload in progress, ignoring file selection');
                    return;
                }
                
                if (e.target.files[0]) {
                    this.loadImage(e.target.files[0]);
                }
            });
        }
        
        // Modal buttons
        const selectFileBtn = document.getElementById('selectFileBtn');
        const changeFileBtn = document.getElementById('changeFileBtn');
        const cancelCropBtn = document.getElementById('cancelCropBtn');
        const saveCropBtn = document.getElementById('saveCropBtn');
        const cropModal = document.getElementById('cropModal');
        
        if (selectFileBtn) {
            selectFileBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                
                // Добавляем защиту от множественных кликов
                if (selectFileBtn.disabled) return;
                selectFileBtn.disabled = true;
                
                console.log('Select file button clicked - opening file picker');
                // Очищаем значение input чтобы можно было выбрать тот же файл повторно
                avatarInput.value = '';
                
                setTimeout(() => {
                    avatarInput.click();
                    setTimeout(() => {
                        selectFileBtn.disabled = false;
                    }, 1000);
                }, 100);
            });
        }
        
        if (changeFileBtn) {
            changeFileBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                
                // Добавляем защиту от множественных кликов
                if (changeFileBtn.disabled) return;
                changeFileBtn.disabled = true;
                
                console.log('Change file button clicked - opening file picker');
                // Очищаем значение input чтобы можно было выбрать тот же файл повторно
                avatarInput.value = '';
                
                setTimeout(() => {
                    avatarInput.click();
                    setTimeout(() => {
                        changeFileBtn.disabled = false;
                    }, 1000);
                }, 100);
            });
        }
        
        if (cancelCropBtn) {
            cancelCropBtn.addEventListener('click', () => this.closeModal());
        }
        
        if (saveCropBtn) {
            // Remove existing event listeners to prevent duplicates
            saveCropBtn.removeEventListener('click', this.cropAndUploadHandler);
            // Create bound handler for removal later
            this.cropAndUploadHandler = () => this.cropAndUpload();
            saveCropBtn.addEventListener('click', this.cropAndUploadHandler);
            console.log('Save crop button event listener attached');
        }
        
        // Close modal on backdrop click, but not on content click
        if (cropModal) {
            cropModal.addEventListener('click', (e) => {
                if (e.target === cropModal) {
                    this.closeModal();
                }
            });
            
            // Prevent ALL clicks inside modal content from bubbling up
            const modalContent = cropModal.querySelector('.modal-content');
            if (modalContent) {
                modalContent.addEventListener('click', (e) => {
                    e.stopPropagation();
                });
            }
            
            // Дополнительная защита - предотвращаем всплытие для всех элементов внутри модального окна
            const allModalElements = cropModal.querySelectorAll('*');
            allModalElements.forEach(element => {
                element.addEventListener('click', (e) => {
                    e.stopPropagation();
                });
            });
        }
        
        // Close buttons
        const closeButtons = cropModal.querySelectorAll('.close');
        if (closeButtons) {
            closeButtons.forEach(btn => {
                btn.addEventListener('click', () => this.closeModal());
            });
        }
        
        // Mouse events for crop area
        document.addEventListener('mousedown', this.handleMouseDown.bind(this));
        document.addEventListener('mousemove', this.handleMouseMove.bind(this));
        document.addEventListener('mouseup', this.handleMouseUp.bind(this));
    }
    
    openModal() {
        console.log('Opening modal');
        const modal = document.getElementById('cropModal');
        const fileSelection = document.getElementById('fileSelection');
        const cropContainer = document.getElementById('cropContainer');
        const saveCropBtn = document.getElementById('saveCropBtn');
        const changeFileBtn = document.getElementById('changeFileBtn');
        
        // Элементы для адаптивного интерфейса
        const newAvatarArea = document.getElementById('newAvatarArea');
        const avatarChangeOptions = document.getElementById('avatarChangeOptions');
        const currentAvatarPreview = document.getElementById('currentAvatarPreview');
        const changeAvatarBtn = document.getElementById('changeAvatarBtn');
        const removeAvatarBtn = document.getElementById('removeAvatarBtn');
        
        console.log('Modal element:', modal);
        
        if (!modal) {
            console.error('Modal element with id "cropModal" not found!');
            alert('Модальное окно не найдено. Проверьте шаблон.');
            return;
        }
        
        // Проверяем, есть ли у пользователя аватарка
        const hasAvatar = window.userData && window.userData.avatarPath && window.userData.avatarPath.trim() !== '';
        console.log('User has avatar:', hasAvatar, 'Avatar path:', window.userData?.avatarPath);
        
        if (hasAvatar) {
            // Если есть аватарка - сразу открываем интерфейс кропа с текущим изображением
            this.loadExistingAvatar(window.userData.avatarPath);
        } else {
            // Показываем интерфейс создания аватарки
            if (newAvatarArea) newAvatarArea.style.display = 'block';
            if (avatarChangeOptions) avatarChangeOptions.style.display = 'none';
            
            // Show file selection, hide crop container
            if (fileSelection) fileSelection.style.display = 'block';
            if (cropContainer) cropContainer.style.display = 'none';
            if (saveCropBtn) saveCropBtn.style.display = 'none';
            if (changeFileBtn) changeFileBtn.style.display = 'none';
        }
        
        console.log('Showing modal');
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
    }

    loadImage(file) {
        console.log('Loading image:', file.name);
        
        // Prevent loading if already uploading
        if (this.isUploading) {
            console.log('Upload in progress, ignoring image load');
            return;
        }
        
        const image = document.getElementById('cropImage');
        const fileSelection = document.getElementById('fileSelection');
        const cropContainer = document.getElementById('cropContainer');
        const saveCropBtn = document.getElementById('saveCropBtn');
        const changeFileBtn = document.getElementById('changeFileBtn');
        
        if (!image) {
            console.error('Image element with id "cropImage" not found!');
            alert('Элемент изображения не найден. Проверьте шаблон.');
            return;
        }
        
        // Validate file type
        if (!file.type.startsWith('image/')) {
            this.showNotification('Пожалуйста, выберите изображение', 'error');
            return;
        }
        
        // Validate file size (5MB)
        if (file.size > 5 * 1024 * 1024) {
            this.showNotification('Размер файла не должен превышать 5MB', 'error');
            return;
        }
        
        const reader = new FileReader();
        reader.onload = (e) => {
            console.log('File read successfully');
            image.src = e.target.result;
            this.imageData = e.target.result;
            this.isExistingAvatar = false; // Mark as new image
            this.savedCropCoords = null; // Reset saved coordinates
            
            image.onload = () => {
                console.log('Image loaded into modal');
                this.setupCropBox(false, null); // false = new image, no saved coords
                this.updatePreviews();
                
                // Show crop container, hide file selection
                if (fileSelection) fileSelection.style.display = 'none';
                if (cropContainer) cropContainer.style.display = 'flex';
                if (saveCropBtn) saveCropBtn.style.display = 'inline-block';
                if (changeFileBtn) changeFileBtn.style.display = 'inline-block';
            };
        };
        reader.readAsDataURL(file);
    }
    
    loadExistingAvatar(avatarPath) {
        console.log('Loading existing avatar for cropping:', avatarPath);
        
        // First, try to get original avatar info from server
        fetch('/profile/avatar/original')
            .then(response => response.json())
            .then(data => {
                if (data.original_avatar_path) {
                    console.log('Found original avatar:', data.original_avatar_path);
                    console.log('Crop coordinates:', data.crop_coordinates);
                    this.loadImageForCropping(data.original_avatar_path, data.crop_coordinates, true);
                } else {
                    console.log('No original avatar found, using current avatar');
                    this.loadImageForCropping(avatarPath, null, true);
                }
            })
            .catch(error => {
                console.log('Failed to get original avatar, using current:', error);
                this.loadImageForCropping(avatarPath, null, true);
            });
    }

    loadImageForCropping(imagePath, cropCoords, isExisting = false) {
        console.log('Loading image for cropping:', imagePath, 'Crop coords:', cropCoords);
        const image = document.getElementById('cropImage');
        const fileSelection = document.getElementById('fileSelection');
        const cropContainer = document.getElementById('cropContainer');
        const saveCropBtn = document.getElementById('saveCropBtn');
        const changeFileBtn = document.getElementById('changeFileBtn');
        const modalHeader = document.querySelector('.modal-header h3');
        
        if (!image) {
            console.error('Image element with id "cropImage" not found!');
            return;
        }
        
        // Update modal title
        if (modalHeader) {
            modalHeader.textContent = isExisting ? 'Редактировать аватар' : 'Создать аватар';
        }
        
        // Store crop coordinates for later use
        this.savedCropCoords = cropCoords;
        this.isExistingAvatar = isExisting;
        
        console.log('loadImageForCrop - setting isExistingAvatar to:', isExisting);
        console.log('loadImageForCrop - cropCoords:', cropCoords);
        
        // Load image into crop interface
        image.src = imagePath + '?t=' + Date.now(); // Add timestamp to prevent caching
        this.imageData = imagePath;
        
        image.onload = () => {
            console.log('Image loaded into crop interface');
            this.setupCropBox(isExisting, cropCoords);
            // updatePreviews() теперь вызывается внутри setupCropBox
            
            // Show crop container, hide file selection
            if (fileSelection) fileSelection.style.display = 'none';
            if (cropContainer) cropContainer.style.display = 'flex';
            if (saveCropBtn) saveCropBtn.style.display = 'inline-block';
            if (changeFileBtn) changeFileBtn.style.display = 'inline-block';
            
            // Update button text to indicate we're editing existing avatar
            if (saveCropBtn) {
                if (isExisting) {
                    saveCropBtn.innerHTML = '<i class="fas fa-save"></i> Сохранить изменения';
                } else {
                    saveCropBtn.innerHTML = '<i class="fas fa-upload"></i> Загрузить аватар';
                }
            }
            
            // Show/hide remove avatar button for existing avatars
            if (isExisting) {
                this.showRemoveAvatarButton();
            } else {
                this.hideRemoveAvatarButton();
            }
        };
    }
    
    showRemoveAvatarButton() {
        const removeBtn = document.getElementById('removeAvatarModalBtn');
        if (removeBtn) {
            removeBtn.style.display = 'inline-block';
            // Add event listener if not already added
            if (!removeBtn.hasAttribute('data-listener-added')) {
                removeBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('Remove avatar button clicked from modal');
                    this.removeAvatar();
                });
                removeBtn.setAttribute('data-listener-added', 'true');
            }
        }
    }
    
    hideRemoveAvatarButton() {
        const removeBtn = document.getElementById('removeAvatarModalBtn');
        if (removeBtn) {
            removeBtn.style.display = 'none';
        }
    }
    
    addRemoveAvatarButton() {
        console.log('addRemoveAvatarButton called - using showRemoveAvatarButton instead');
        this.showRemoveAvatarButton();
    }
    
    closeModal() {
        const modal = document.getElementById('cropModal');
        const avatarInput = document.getElementById('avatarInput');
        const fileSelection = document.getElementById('fileSelection');
        const cropContainer = document.getElementById('cropContainer');
        const saveCropBtn = document.getElementById('saveCropBtn');
        const changeFileBtn = document.getElementById('changeFileBtn');
        const removeAvatarModalBtn = document.getElementById('removeAvatarModalBtn');
        const modalHeader = document.querySelector('.modal-header h3');
        
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = '';
        }
        
        // Reset modal title
        if (modalHeader) {
            modalHeader.textContent = 'Обрезать изображение';
        }
        
        // Reset to initial state
        if (fileSelection) fileSelection.style.display = 'block';
        if (cropContainer) cropContainer.style.display = 'none';
        if (saveCropBtn) {
            saveCropBtn.style.display = 'none';
            saveCropBtn.innerHTML = '<i class="fas fa-upload"></i> Загрузить аватар'; // Reset button text
        }
        if (changeFileBtn) changeFileBtn.style.display = 'none';
        
        // Hide the remove avatar button
        if (removeAvatarModalBtn) {
            removeAvatarModalBtn.style.display = 'none';
        }
        
        // Reset file input
        if (avatarInput) {
            avatarInput.value = '';
        }
        
        // Reset adaptive interface elements
        const newAvatarArea = document.getElementById('newAvatarArea');
        const avatarChangeOptions = document.getElementById('avatarChangeOptions');
        if (newAvatarArea) newAvatarArea.style.display = 'block';
        if (avatarChangeOptions) avatarChangeOptions.style.display = 'none';
    }
    
    setupCropBox(existingAvatar = false, savedCropCoords = null) {
        const image = document.getElementById('cropImage');
        const cropBox = document.getElementById('cropBox');
        
        console.log('setupCropBox called:', { 
            existingAvatar, 
            savedCropCoords, 
            imageFound: !!image, 
            cropBoxFound: !!cropBox 
        });
        
        if (!image || !cropBox) {
            console.error('setupCropBox: Missing required elements:', { image: !!image, cropBox: !!cropBox });
            return;
        }
        
        // Reset ready flag at start of setup
        this.cropBoxReady = false;
        
        // Store cropBox reference for later use
        this.cropBox = cropBox;
        console.log('Stored cropBox reference:', this.cropBox);
        
        // Wait for image to be loaded and get actual dimensions
        setTimeout(() => {
            const imageRect = image.getBoundingClientRect();
            const container = image.parentElement;
            const containerRect = container.getBoundingClientRect();
            
            // Calculate relative position within the container
            const offsetX = imageRect.left - containerRect.left;
            const offsetY = imageRect.top - containerRect.top;
            
            let size, left, top;
            
            if (savedCropCoords && existingAvatar) {
                // Используем сохраненные координаты кропа
                console.log('Using saved crop coordinates:', savedCropCoords);
                
                // Координаты сохранены относительно оригинального изображения (0-1)
                // Конвертируем их в пиксели текущего размера
                const cropWidth = imageRect.width * savedCropCoords.width;
                const cropHeight = imageRect.height * savedCropCoords.height;
                size = Math.min(cropWidth, cropHeight); // Используем меньшую сторону для квадрата
                
                left = offsetX + (imageRect.width * savedCropCoords.x);
                top = offsetY + (imageRect.height * savedCropCoords.y);
                
                // Убеждаемся что crop box не выходит за границы
                if (left + size > offsetX + imageRect.width) {
                    left = offsetX + imageRect.width - size;
                }
                if (top + size > offsetY + imageRect.height) {
                    top = offsetY + imageRect.height - size;
                }
                
            } else if (existingAvatar) {
                // Для существующей аватарки без сохраненных координат - показываем весь контент
                size = Math.min(imageRect.width, imageRect.height);
                
                // Центрируем по большей стороне
                if (imageRect.width > imageRect.height) {
                    left = offsetX + (imageRect.width - size) / 2;
                    top = offsetY;
                } else {
                    left = offsetX;
                    top = offsetY + (imageRect.height - size) / 2;
                }
            } else {
                // Для нового изображения - 60% от меньшей стороны, по центру
                size = Math.min(imageRect.width, imageRect.height) * 0.6;
                left = offsetX + (imageRect.width - size) / 2;
                top = offsetY + (imageRect.height - size) / 2;
            }
            
            cropBox.style.width = size + 'px';
            cropBox.style.height = size + 'px';
            cropBox.style.left = left + 'px';
            cropBox.style.top = top + 'px';
            
            console.log('Setup crop box:', { size, left, top, existingAvatar });
            
            this.cropBox = cropBox;
            this.cropBoxReady = true; // Flag to indicate cropBox is ready
            console.log('CropBox setup completed, ready for use');
            
            // Обновляем превью после установки crop box
            setTimeout(() => {
                this.updatePreviews();
            }, 50);
        }, 100);
    }
    
    handleMouseDown(e) {
        const target = e.target;
        
        if (target.classList.contains('crop-handle')) {
            this.isResizing = true;
            this.currentHandle = target.className.split(' ')[1];
            this.cropBox.classList.add('dragging');
            e.preventDefault();
        } else if (target.id === 'cropBox') {
            this.isDragging = true;
            this.cropBox.classList.add('dragging');
            e.preventDefault();
        }
        
        if (this.isDragging || this.isResizing) {
            this.startX = e.clientX;
            this.startY = e.clientY;
        }
    }
    
    handleMouseMove(e) {
        if (!this.isDragging && !this.isResizing) return;
        
        const deltaX = e.clientX - this.startX;
        const deltaY = e.clientY - this.startY;
        
        if (this.isDragging) {
            this.dragCropBox(deltaX, deltaY);
        } else if (this.isResizing) {
            this.resizeCropBox(deltaX, deltaY);
        }
        
        this.startX = e.clientX;
        this.startY = e.clientY;
        this.updatePreviews();
    }
    
    handleMouseUp() {
        this.isDragging = false;
        this.isResizing = false;
        this.currentHandle = null;
        if (this.cropBox) {
            this.cropBox.classList.remove('dragging');
        }
    }
    
    dragCropBox(deltaX, deltaY) {
        const cropBox = this.cropBox;
        const image = document.getElementById('cropImage');
        
        if (!cropBox || !image) return;
        
        const imageRect = image.getBoundingClientRect();
        const container = image.parentElement;
        const containerRect = container.getBoundingClientRect();
        
        const offsetX = imageRect.left - containerRect.left;
        const offsetY = imageRect.top - containerRect.top;
        
        const currentLeft = parseInt(cropBox.style.left) || 0;
        const currentTop = parseInt(cropBox.style.top) || 0;
        const boxWidth = parseInt(cropBox.style.width) || 0;
        const boxHeight = parseInt(cropBox.style.height) || 0;
        
        const minLeft = offsetX;
        const minTop = offsetY;
        const maxLeft = offsetX + imageRect.width - boxWidth;
        const maxTop = offsetY + imageRect.height - boxHeight;
        
        const newLeft = Math.max(minLeft, Math.min(maxLeft, currentLeft + deltaX));
        const newTop = Math.max(minTop, Math.min(maxTop, currentTop + deltaY));
        
        cropBox.style.left = newLeft + 'px';
        cropBox.style.top = newTop + 'px';
    }
    
    resizeCropBox(deltaX, deltaY) {
        const cropBox = this.cropBox;
        const image = document.getElementById('cropImage');
        
        if (!cropBox || !image) return;
        
        const imageRect = image.getBoundingClientRect();
        const container = image.parentElement;
        const containerRect = container.getBoundingClientRect();
        
        // Границы изображения относительно контейнера
        const imageLeft = imageRect.left - containerRect.left;
        const imageTop = imageRect.top - containerRect.top;
        const imageRight = imageLeft + imageRect.width;
        const imageBottom = imageTop + imageRect.height;
        
        // Текущие параметры crop box
        const currentLeft = parseFloat(cropBox.style.left) || 0;
        const currentTop = parseFloat(cropBox.style.top) || 0;
        const currentSize = parseFloat(cropBox.style.width) || 100;
        
        // Минимальный и максимальный размер
        const minSize = 30;
        const maxSizeX = imageRight - currentLeft; // Максимальная ширина от текущей позиции
        const maxSizeY = imageBottom - currentTop; // Максимальная высота от текущей позиции
        
        let newSize = currentSize;
        let newLeft = currentLeft;
        let newTop = currentTop;
        
        console.log('Current handle:', this.currentHandle);
        console.log('Current state:', { currentLeft, currentTop, currentSize });
        console.log('Image bounds:', { imageLeft, imageTop, imageRight, imageBottom });
        console.log('Delta:', { deltaX, deltaY });
        
        // Вычисляем новый размер в зависимости от ручки
        switch (this.currentHandle) {
            case 'crop-handle-se': // Правый нижний угол
                newSize = Math.max(minSize, currentSize + Math.min(deltaX, deltaY));
                // Проверяем что не выходим за границы
                newSize = Math.min(newSize, maxSizeX, maxSizeY);
                break;
                
            case 'crop-handle-sw': // Левый нижний угол  
                newSize = Math.max(minSize, currentSize - Math.max(deltaX, -deltaY));
                // Ограничиваем размер доступным пространством
                const maxSizeFromRight = imageRight - imageLeft; // Максимальный размер до правой границы
                const maxSizeFromBottom = imageBottom - currentTop; // Максимальный размер до нижней границы
                newSize = Math.min(newSize, maxSizeFromRight, maxSizeFromBottom);
                // Вычисляем новую левую позицию (правый край остается на месте)
                newLeft = currentLeft + currentSize - newSize;
                // Убеждаемся что не выходим за левую границу
                if (newLeft < imageLeft) {
                    newSize = currentLeft + currentSize - imageLeft;
                    newLeft = imageLeft;
                }
                break;
                
            case 'crop-handle-ne': // Правый верхний угол
                newSize = Math.max(minSize, currentSize + Math.min(deltaX, -deltaY));
                // Ограничиваем размер
                const maxSizeFromRightNE = imageRight - currentLeft;
                const maxSizeFromTopNE = imageBottom - imageTop;
                newSize = Math.min(newSize, maxSizeFromRightNE, maxSizeFromTopNE);
                // Вычисляем новую верхнюю позицию (нижний край остается на месте)
                newTop = currentTop + currentSize - newSize;
                // Убеждаемся что не выходим за верхнюю границу
                if (newTop < imageTop) {
                    newSize = currentTop + currentSize - imageTop;
                    newTop = imageTop;
                }
                break;
                
            case 'crop-handle-nw': // Левый верхний угол
                newSize = Math.max(minSize, currentSize - Math.max(deltaX, deltaY));
                // Ограничиваем размер доступным пространством
                const maxSizeFromRightNW = imageRight - imageLeft;
                const maxSizeFromBottomNW = imageBottom - imageTop;
                newSize = Math.min(newSize, maxSizeFromRightNW, maxSizeFromBottomNW);
                // Вычисляем новые позиции (правый нижний угол остается на месте)
                newLeft = currentLeft + currentSize - newSize;
                newTop = currentTop + currentSize - newSize;
                // Проверяем границы
                if (newLeft < imageLeft) {
                    newSize = currentLeft + currentSize - imageLeft;
                    newLeft = imageLeft;
                    newTop = currentTop + currentSize - newSize;
                }
                if (newTop < imageTop) {
                    newSize = Math.min(newSize, currentTop + currentSize - imageTop);
                    newLeft = currentLeft + currentSize - newSize;
                    newTop = imageTop;
                }
                break;
        }
        
        // Финальная проверка: убеждаемся что crop box полностью внутри изображения
        newSize = Math.max(minSize, newSize);
        newLeft = Math.max(imageLeft, Math.min(newLeft, imageRight - newSize));
        newTop = Math.max(imageTop, Math.min(newTop, imageBottom - newSize));
        
        // Применяем изменения
        cropBox.style.left = newLeft + 'px';
        cropBox.style.top = newTop + 'px';
        cropBox.style.width = newSize + 'px';
        cropBox.style.height = newSize + 'px';
        
        console.log('Applied values:', { newLeft, newTop, newSize });
        console.log('---');
        
        // Обновляем превью
        this.updatePreviews();
    }
    
    updatePreviews() {
        const image = document.getElementById('cropImage');
        const cropBox = this.cropBox;
        
        if (!image || !cropBox || !image.complete) return;
        
        const imageRect = image.getBoundingClientRect();
        const container = image.parentElement;
        const containerRect = container.getBoundingClientRect();
        
        const offsetX = imageRect.left - containerRect.left;
        const offsetY = imageRect.top - containerRect.top;
        
        const cropLeft = parseInt(cropBox.style.left) || 0;
        const cropTop = parseInt(cropBox.style.top) || 0;
        const cropWidth = parseInt(cropBox.style.width) || 0;
        const cropHeight = parseInt(cropBox.style.height) || 0;
        
        // Calculate relative position within the image
        const relativeX = cropLeft - offsetX;
        const relativeY = cropTop - offsetY;
        
        // Convert to actual image coordinates
        const scaleX = image.naturalWidth / imageRect.width;
        const scaleY = image.naturalHeight / imageRect.height;
        
        const realX = relativeX * scaleX;
        const realY = relativeY * scaleY;
        const realWidth = cropWidth * scaleX;
        const realHeight = cropHeight * scaleY;
        
        this.drawPreview('previewSquare', realX, realY, realWidth, realHeight, false);
        this.drawPreview('previewCircle', realX, realY, realWidth, realHeight, true);
    }
    
    drawPreview(canvasId, x, y, width, height, isCircle) {
        const canvas = document.getElementById(canvasId);
        const ctx = canvas.getContext('2d');
        const image = document.getElementById('cropImage');
        
        if (!canvas || !ctx || !image) return;
        
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        if (isCircle) {
            ctx.save();
            ctx.beginPath();
            ctx.arc(canvas.width / 2, canvas.height / 2, canvas.width / 2, 0, Math.PI * 2);
            ctx.clip();
        }
        
        try {
            ctx.drawImage(
                image,
                x, y, width, height,
                0, 0, canvas.width, canvas.height
            );
        } catch (e) {
            console.warn('Error drawing preview:', e);
        }
        
        if (isCircle) {
            ctx.restore();
        }
    }
    
    getCroppedImage() {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const image = document.getElementById('cropImage');
        const cropBox = this.cropBox;
        
        console.log('getCroppedImage - checking elements:', { 
            image: !!image, 
            cropBox: !!cropBox,
            imageLoaded: image ? image.complete && image.naturalWidth > 0 : false,
            cropBoxVisible: cropBox ? cropBox.style.display !== 'none' : false,
            cropBoxDimensions: cropBox ? {
                width: cropBox.style.width,
                height: cropBox.style.height,
                left: cropBox.style.left,
                top: cropBox.style.top
            } : null
        });
        
        if (!image) {
            console.error('No image element found with ID cropImage');
            return null;
        }
        
        if (!cropBox) {
            console.error('No cropBox element found - this.cropBox is null');
            return null;
        }
        
        if (!image.complete || image.naturalWidth === 0) {
            console.error('Image not loaded or invalid - complete:', image.complete, 'naturalWidth:', image.naturalWidth);
            return null;
        }
        
        // Check if cropBox has valid dimensions
        const boxWidth = parseInt(cropBox.style.width) || 0;
        const boxHeight = parseInt(cropBox.style.height) || 0;
        
        if (boxWidth <= 0 || boxHeight <= 0) {
            console.error('CropBox has invalid dimensions:', { width: boxWidth, height: boxHeight });
            return null;
        }
        
        const imageRect = image.getBoundingClientRect();
        const container = image.parentElement;
        const containerRect = container.getBoundingClientRect();
        
        // Получаем координаты crop box относительно контейнера
        const cropLeft = parseInt(cropBox.style.left) || 0;
        const cropTop = parseInt(cropBox.style.top) || 0;
        const cropWidth = parseInt(cropBox.style.width) || 100;
        const cropHeight = parseInt(cropBox.style.height) || 100;
        
        console.log('Crop box position:', { cropLeft, cropTop, cropWidth, cropHeight });
        console.log('Image rect:', imageRect);
        console.log('Container rect:', containerRect);
        
        // Рассчитываем позицию изображения относительно контейнера
        const imageOffsetX = imageRect.left - containerRect.left;
        const imageOffsetY = imageRect.top - containerRect.top;
        
        console.log('Image offset:', { imageOffsetX, imageOffsetY });
        
        // Рассчитываем область обрезки относительно изображения
        const relativeX = Math.max(0, cropLeft - imageOffsetX);
        const relativeY = Math.max(0, cropTop - imageOffsetY);
        const relativeWidth = Math.min(cropWidth, imageRect.width - relativeX);
        const relativeHeight = Math.min(cropHeight, imageRect.height - relativeY);
        
        console.log('Relative crop area:', { relativeX, relativeY, relativeWidth, relativeHeight });
        
        // Преобразуем в координаты оригинального изображения
        const scaleX = image.naturalWidth / imageRect.width;
        const scaleY = image.naturalHeight / imageRect.height;
        
        const realX = relativeX * scaleX;
        const realY = relativeY * scaleY;
        const realWidth = relativeWidth * scaleX;
        const realHeight = relativeHeight * scaleY;
        
        console.log('Final crop coordinates:', { realX, realY, realWidth, realHeight });
        console.log('Image natural size:', { width: image.naturalWidth, height: image.naturalHeight });
        
        // Увеличиваем размер canvas для лучшего качества (можно до 512px)
        canvas.width = 512;
        canvas.height = 512;
        
        try {
            // Улучшаем качество рендеринга
            ctx.imageSmoothingEnabled = true;
            ctx.imageSmoothingQuality = 'high';
            
            ctx.drawImage(
                image,
                realX, realY, realWidth, realHeight,
                0, 0, canvas.width, canvas.height
            );
            
            // Увеличиваем качество JPEG до 0.95
            return canvas.toDataURL('image/jpeg', 0.95);
        } catch (e) {
            console.error('Error creating cropped image:', e);
            return null;
        }
    }
    
    cropAndUpload(attemptCount = 0) {
        console.log('cropAndUpload called - checking readiness... attempt:', attemptCount);
        console.log('CropBox ready flag:', this.cropBoxReady);
        console.log('CropBox element:', this.cropBox);
        
        // Prevent multiple simultaneous uploads
        if (this.isUploading) {
            console.log('Upload already in progress, skipping...');
            return;
        }
        
        // Limit retry attempts to avoid infinite recursion
        if (attemptCount > 5) {
            console.error('cropAndUpload: Too many attempts, giving up');
            this.showNotification('Ошибка при обрезке изображения - превышено количество попыток', 'error');
            return;
        }
        
        // Wait for cropBox to be properly initialized
        if (!this.cropBoxReady || !this.cropBox) {
            console.log('CropBox not ready, attempting to find and initialize...');
            
            const cropBoxElement = document.getElementById('cropBox');
            if (cropBoxElement && cropBoxElement.style.width && cropBoxElement.style.height) {
                console.log('Found initialized cropBox in DOM, using it...');
                this.cropBox = cropBoxElement;
                this.cropBoxReady = true;
            } else {
                console.log('CropBox not initialized yet, waiting 200ms...');
                setTimeout(() => this.cropAndUpload(attemptCount + 1), 200);
                return;
            }
        }
        
        const croppedImage = this.getCroppedImage();
        
        if (!croppedImage) {
            console.error('Failed to create cropped image');
            console.log('Image element:', document.getElementById('cropImage'));
            console.log('Crop box element:', this.cropBox);
            
            // If we still can't create cropped image, try to reinitialize cropBox
            if (attemptCount < 3) {
                console.log('Retrying with fresh cropBox reference...');
                this.cropBox = document.getElementById('cropBox');
                this.cropBoxReady = false; // Reset ready flag
                setTimeout(() => this.cropAndUpload(attemptCount + 1), 300);
                return;
            }
            
            this.showNotification('Ошибка при обрезке изображения - проверьте выделенную область', 'error');
            return;
        }
        
        console.log('Cropped image created successfully, proceeding with upload...');
        
        // Set upload flag to prevent multiple uploads
        this.isUploading = true;
        
        // Show loading state
        const saveCropBtn = document.getElementById('saveCropBtn');
        const originalText = saveCropBtn.textContent;
        saveCropBtn.disabled = true;
        saveCropBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Сохранение...';
        
        // Get current crop coordinates relative to the image (0-1)
        const image = document.getElementById('cropImage');
        const cropBox = document.getElementById('cropBox');
        const imageRect = image.getBoundingClientRect();
        const container = image.parentElement;
        const containerRect = container.getBoundingClientRect();
        
        const offsetX = imageRect.left - containerRect.left;
        const offsetY = imageRect.top - containerRect.top;
        
        const cropLeft = parseFloat(cropBox.style.left) || 0;
        const cropTop = parseFloat(cropBox.style.top) || 0;
        const cropWidth = parseFloat(cropBox.style.width) || 100;
        const cropHeight = parseFloat(cropBox.style.height) || 100;
        
        // Convert to relative coordinates (0-1)
        const relativeX = (cropLeft - offsetX) / imageRect.width;
        const relativeY = (cropTop - offsetY) / imageRect.height;
        const relativeWidth = cropWidth / imageRect.width;
        const relativeHeight = cropHeight / imageRect.height;
        
        console.log('Crop coordinates (relative):', {
            x: relativeX,
            y: relativeY, 
            width: relativeWidth,
            height: relativeHeight
        });
        
        const formData = new FormData();
        
        console.log('Preparing FormData...');
        console.log('isExistingAvatar flag:', this.isExistingAvatar);
        
        // Check if this is an existing avatar update or new upload
        if (this.isExistingAvatar) {
            console.log('Processing as existing avatar update');
            // This is a crop update of existing image
            formData.append('crop_update', 'true');
            formData.append('cropped_image', croppedImage);
        } else {
            console.log('Processing as new file upload');
            // This is a new file upload
            const avatarInput = document.getElementById('avatarInput');
            console.log('Avatar input element:', avatarInput);
            console.log('Avatar input files:', avatarInput ? avatarInput.files : 'no element');
            
            if (avatarInput && avatarInput.files[0]) {
                console.log('Found file in input:', avatarInput.files[0].name);
                formData.append('avatar', avatarInput.files[0]);
                formData.append('cropped_image', croppedImage);
            } else {
                console.error('No file found in avatar input for new upload');
                console.log('Falling back to crop-only mode...');
                // Fallback: treat as existing image crop update
                formData.append('crop_update', 'true');
                formData.append('cropped_image', croppedImage);
            }
        }
        
        // Add crop coordinates
        formData.append('crop_x', relativeX);
        formData.append('crop_y', relativeY);
        formData.append('crop_width', relativeWidth);
        formData.append('crop_height', relativeHeight);
        
        fetch('/profile/avatar', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            console.log('Upload response:', data);
            if (data.success) {
                this.showNotification(data.message || 'Аватарка успешно обновлена!', 'success');
                
                // Update avatar display
                this.updateAvatarDisplay(data.avatar_path);
                this.closeModal();
            } else {
                this.showNotification(data.error || 'Ошибка загрузки аватарки', 'error');
            }
        })
        .catch(error => {
            console.error('Ошибка загрузки:', error);
            this.showNotification('Ошибка загрузки аватарки', 'error');
        })
        .finally(() => {
            // Reset upload flag
            this.isUploading = false;
            
            saveCropBtn.disabled = false;
            saveCropBtn.innerHTML = originalText;
        });
    }
    
    updateAvatarDisplay(avatarPath) {
        console.log('updateAvatarDisplay called with:', avatarPath);
        
        const avatarImage = document.getElementById('avatarImage');
        const defaultAvatar = document.getElementById('defaultAvatar');
        const timestamp = Date.now();
        
        console.log('Avatar elements found:', { avatarImage: !!avatarImage, defaultAvatar: !!defaultAvatar });
        
        // avatarPath уже содержит полный путь (например: /data/avatars/filename.jpg)
        const fullPath = `${avatarPath}?t=${timestamp}`;
        console.log('Full avatar path:', fullPath);
        
        if (avatarImage) {
            console.log('Updating existing avatar image');
            
            // Set up handlers BEFORE changing src to avoid false events
            const handleLoad = () => {
                console.log('Avatar image loaded successfully');
                avatarImage.style.display = 'block';
                if (defaultAvatar) defaultAvatar.style.display = 'none';
                // Remove handlers to prevent memory leaks
                avatarImage.removeEventListener('load', handleLoad);
                avatarImage.removeEventListener('error', handleError);
            };
            
            const handleError = (e) => {
                console.error('Avatar image failed to load:', e);
                avatarImage.style.display = 'none';
                if (defaultAvatar) defaultAvatar.style.display = 'block';
                // Remove handlers to prevent memory leaks
                avatarImage.removeEventListener('load', handleLoad);
                avatarImage.removeEventListener('error', handleError);
            };
            
            // Remove any existing handlers
            avatarImage.onload = null;
            avatarImage.onerror = null;
            
            // Add new handlers
            avatarImage.addEventListener('load', handleLoad, { once: true });
            avatarImage.addEventListener('error', handleError, { once: true });
            
            // Now set the new source
            avatarImage.src = fullPath;
            avatarImage.style.display = 'block';
        } else if (defaultAvatar) {
            console.log('Creating new avatar image to replace default');
            // Replace icon with image
            const newImg = document.createElement('img');
            newImg.src = fullPath;
            newImg.alt = 'Аватар';
            newImg.id = 'avatarImage';
            newImg.style.display = 'block';
            
            newImg.onload = () => {
                console.log('New avatar image loaded successfully');
                defaultAvatar.style.display = 'none';
            };
            
            newImg.onerror = (e) => {
                console.error('New avatar image failed to load:', e);
                newImg.remove();
                defaultAvatar.style.display = 'block';
            };
            
            defaultAvatar.parentElement.appendChild(newImg);
            defaultAvatar.style.display = 'none';
        } else {
            console.error('No avatar image or default avatar element found');
        }
        
        // Update window.userData to reflect new avatar
        if (window.userData) {
            window.userData.avatarPath = avatarPath;
        }
    }
    
    showNotification(message, type = 'info') {
        console.log('showNotification called with:', { message, type });
        
        // Try to use existing notification system from profile.js
        if (typeof window.showNotification === 'function') {
            console.log('Using global notification system');
            window.showNotification(message, type);
            return;
        }
        
        console.log('Using fallback notification system');
        // Fallback notification if profile.js isn't loaded
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        // Calculate position based on existing notifications
        const existingNotifications = document.querySelectorAll('.notification');
        let topPosition = 20;
        
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
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
    
    async removeAvatar() {
        if (!confirm('Вы уверены, что хотите удалить аватар?')) {
            return;
        }
        
        try {
            const response = await fetch('/profile/remove-avatar', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            if (response.ok) {
                const result = await response.json();
                console.log('Avatar removed successfully:', result);
                
                // Обновляем отображение аватарки
                this.resetAvatarDisplay();
                
                // Обновляем userData
                if (window.userData) {
                    window.userData.avatarPath = '';
                }
                
                // Закрываем модальное окно
                this.closeModal();
                
                this.showNotification('Аватар успешно удален', 'success');
            } else {
                const error = await response.json();
                console.error('Failed to remove avatar:', error);
                this.showNotification(error.error || 'Ошибка при удалении аватара', 'error');
            }
        } catch (error) {
            console.error('Network error:', error);
            this.showNotification('Ошибка сети. Попробуйте позже.', 'error');
        }
    }
    
    resetAvatarDisplay() {
        const avatarImage = document.getElementById('avatarImage');
        const defaultAvatar = document.getElementById('defaultAvatar');
        
        if (avatarImage) {
            avatarImage.remove();
        }
        
        if (defaultAvatar) {
            defaultAvatar.style.display = 'block';
        }
    }
}

// Initialize avatar crop functionality
document.addEventListener('DOMContentLoaded', function() {
    // Prevent multiple initialization
    if (window.avatarCropInstance) {
        console.log('AvatarCrop already initialized, skipping...');
        return;
    }
    
    const avatarCrop = new AvatarCrop();
    window.avatarCropInstance = avatarCrop;
    
    console.log('AvatarCrop initialized successfully');
});

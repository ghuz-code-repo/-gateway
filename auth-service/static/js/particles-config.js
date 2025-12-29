// Particles.js configuration
// Shared configuration for all pages with particles background

document.addEventListener('DOMContentLoaded', function() {
    // Check if particles-js element exists
    if (!document.getElementById('particles-js')) {
        console.log('particles-config.js: No #particles-js element found');
        return;
    }
    
    // Check if particlesJS function is available
    if (typeof particlesJS === 'undefined') {
        console.log('particles-config.js: particlesJS not loaded');
        return;
    }
    
    console.log('particles-config.js: Initializing particles...');
    
    particlesJS('particles-js', {
        "particles": {
            "number": { 
                "value": 120, 
                "density": { "enable": true, "value_area": 800 } 
            },
            "color": { "value": "#c4a668" },
            "shape": { 
                "type": "polygon", 
                "stroke": { "width": 1, "color": "#c4a668" }, 
                "polygon": { "nb_sides": 6 } 
            },
            "opacity": { 
                "value": 0.2, 
                "random": true, 
                "anim": { "enable": true, "speed": 0.5, "opacity_min": 0.05, "sync": false } 
            },
            "size": { "value": 4, "random": true },
            "line_linked": { 
                "enable": true, 
                "distance": 180, 
                "color": "#c4a668", 
                "opacity": 0.15, 
                "width": 1 
            },
            "move": { 
                "enable": true, 
                "speed": 0.8, 
                "direction": "none", 
                "random": true, 
                "straight": false, 
                "out_mode": "out" 
            }
        },
        "interactivity": {
            "detect_on": "canvas",
            "events": { 
                "onhover": { "enable": true, "mode": "bubble" }, 
                "onclick": { "enable": true, "mode": "push" } 
            },
            "modes": { 
                "bubble": { "distance": 200, "size": 6, "duration": 2, "opacity": 0.6 } 
            }
        },
        "retina_detect": true
    });
    
    console.log('particles-config.js: Particles initialized');
});

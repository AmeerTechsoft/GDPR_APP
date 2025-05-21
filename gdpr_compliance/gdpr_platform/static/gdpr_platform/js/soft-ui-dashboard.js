// Soft UI Dashboard JavaScript

// Sidebar functionality
const sidenavToggler = document.querySelector('.sidenav-toggler');
const body = document.querySelector('body');
const className = 'g-sidenav-pinned';

if (sidenavToggler) {
    sidenavToggler.addEventListener('click', function() {
        body.classList.toggle(className);
    });
}

// Initialize tooltips
const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
tooltipTriggerList.map(function(tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
});

// Initialize popovers
const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
popoverTriggerList.map(function(popoverTriggerEl) {
    return new bootstrap.Popover(popoverTriggerEl);
});

// Perfect Scrollbar initialization
if (document.querySelector('.sidenav')) {
    const sidenav = document.querySelector('.sidenav');
    const ps = new PerfectScrollbar(sidenav);
}

// Alert auto-close
const alerts = document.querySelectorAll('.alert[data-timeout]');
alerts.forEach(alert => {
    const timeout = alert.getAttribute('data-timeout');
    if (timeout) {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, parseInt(timeout));
    }
});

// Form validation
const forms = document.querySelectorAll('.needs-validation');
forms.forEach(form => {
    form.addEventListener('submit', event => {
        if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }
        form.classList.add('was-validated');
    });
});

// Table search functionality
function initializeTableSearch(tableId, searchId) {
    const searchInput = document.getElementById(searchId);
    const table = document.getElementById(tableId);
    
    if (searchInput && table) {
        searchInput.addEventListener('keyup', function() {
            const searchText = this.value.toLowerCase();
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                let found = false;
                
                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell.textContent.toLowerCase().indexOf(searchText) > -1) {
                        found = true;
                        break;
                    }
                }
                
                row.style.display = found ? '' : 'none';
            }
        });
    }
}

// Table sorting functionality
function sortTable(table, column, asc = true) {
    const dirModifier = asc ? 1 : -1;
    const tBody = table.tBodies[0];
    const rows = Array.from(tBody.querySelectorAll('tr'));
    
    const sortedRows = rows.sort((a, b) => {
        const aColText = a.querySelector(`td:nth-child(${column + 1})`).textContent.trim();
        const bColText = b.querySelector(`td:nth-child(${column + 1})`).textContent.trim();
        
        return aColText > bColText ? (1 * dirModifier) : (-1 * dirModifier);
    });
    
    while (tBody.firstChild) {
        tBody.removeChild(tBody.firstChild);
    }
    
    tBody.append(...sortedRows);
    
    table.querySelectorAll('th').forEach(th => th.classList.remove('asc', 'desc'));
    table.querySelector(`th:nth-child(${column + 1})`).classList.toggle('asc', asc);
    table.querySelector(`th:nth-child(${column + 1})`).classList.toggle('desc', !asc);
}

// Chart initialization (if Chart.js is included)
function initializeCharts() {
    if (typeof Chart !== 'undefined') {
        // Line chart configuration
        const lineConfig = {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Data',
                    tension: 0.4,
                    borderWidth: 2,
                    borderColor: '#cb0c9f',
                    backgroundColor: 'rgba(203, 12, 159, 0.2)',
                    fill: true,
                    data: []
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        grid: {
                            drawBorder: false,
                            display: true,
                            drawOnChartArea: true,
                            drawTicks: false,
                            borderDash: [5, 5]
                        },
                        ticks: {
                            display: true,
                            padding: 10,
                            color: '#b2b9bf',
                            font: {
                                size: 11,
                                family: "Open Sans",
                                style: 'normal',
                                lineHeight: 2
                            }
                        }
                    },
                    x: {
                        grid: {
                            drawBorder: false,
                            display: false,
                            drawOnChartArea: false,
                            drawTicks: false,
                            borderDash: [5, 5]
                        },
                        ticks: {
                            display: true,
                            color: '#b2b9bf',
                            padding: 20,
                            font: {
                                size: 11,
                                family: "Open Sans",
                                style: 'normal',
                                lineHeight: 2
                            }
                        }
                    }
                }
            }
        };
        
        // Initialize charts where needed
        const chartElements = document.querySelectorAll('.chart-line');
        chartElements.forEach(element => {
            new Chart(element, lineConfig);
        });
    }
}

// Initialize all components when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initializeCharts();
    
    // Initialize table search
    const tables = document.querySelectorAll('table[data-search]');
    tables.forEach(table => {
        const searchId = table.getAttribute('data-search');
        initializeTableSearch(table.id, searchId);
    });
    
    // Initialize sortable tables
    const sortableTables = document.querySelectorAll('table.sortable');
    sortableTables.forEach(table => {
        const headerCells = table.querySelectorAll('th');
        headerCells.forEach((headerCell, index) => {
            headerCell.addEventListener('click', () => {
                const isAscending = headerCell.classList.contains('asc');
                sortTable(table, index, !isAscending);
            });
        });
    });
});
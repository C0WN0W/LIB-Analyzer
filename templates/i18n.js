// 多语言配置
const translations = {
    'zh-CN': {
        // 头部
        'app_title': 'LIB Analyzer',
        'stat_files': '文件',
        'stat_size': '大小',

        // 上传区域
        'upload_title': '拖放 .lib 文件到这里',
        'upload_hint': '或点击选择文件',

        // 标签页
        'tab_files': '📁 文件列表',
        'tab_symbols': '🔣 符号表',
        'tab_search': '🔍 搜索',
        'tab_details': '📊 详细信息',

        // 文件列表
        'table_index': '索引',
        'table_name': '名称',
        'table_size': '大小',
        'table_type': '类型',
        'table_actions': '操作',
        'btn_view': '👁️ 查看',
        'btn_extract': '💾 提取',

        // 空状态
        'empty_files': '请先上传一个 .lib 文件',
        'empty_symbols': '请先上传一个 .lib 文件',
        'empty_search': '输入关键字开始搜索',
        'empty_details': '点击文件列表中的文件查看详细信息',

        // 搜索
        'search_placeholder': '输入关键字搜索...',
        'btn_search': '🔍 搜索',
        'search_results': '搜索结果',
        'search_no_results': '未找到匹配结果',

        // 详细信息
        'detail_file_info': '文件信息',
        'detail_coff_info': 'COFF 对象文件',
        'detail_hex_preview': '十六进制预览',
        'detail_sections': '节列表',

        // 加载
        'loading': '处理中...',

        // 错误
        'error_upload': '上传失败',
        'error_load': '加载失败',
        'error_search': '搜索失败',
    },
    'en-US': {
        // Header
        'app_title': 'LIB Analyzer',
        'stat_files': 'Files',
        'stat_size': 'Size',

        // Upload
        'upload_title': 'Drop .lib file here',
        'upload_hint': 'or click to select file',

        // Tabs
        'tab_files': '📁 Files',
        'tab_symbols': '🔣 Symbols',
        'tab_search': '🔍 Search',
        'tab_details': '📊 Details',

        // File list
        'table_index': 'Index',
        'table_name': 'Name',
        'table_size': 'Size',
        'table_type': 'Type',
        'table_actions': 'Actions',
        'btn_view': '👁️ View',
        'btn_extract': '💾 Extract',

        // Empty states
        'empty_files': 'Please upload a .lib file first',
        'empty_symbols': 'Please upload a .lib file first',
        'empty_search': 'Enter keyword to search',
        'empty_details': 'Click a file in the list to view details',

        // Search
        'search_placeholder': 'Enter keyword to search...',
        'btn_search': '🔍 Search',
        'search_results': 'Search Results',
        'search_no_results': 'No results found',

        // Details
        'detail_file_info': 'File Information',
        'detail_coff_info': 'COFF Object File',
        'detail_hex_preview': 'Hex Preview',
        'detail_sections': 'Sections',

        // Loading
        'loading': 'Processing...',

        // Errors
        'error_upload': 'Upload failed',
        'error_load': 'Load failed',
        'error_search': 'Search failed',
    }
};

// 当前语言
let currentLang = localStorage.getItem('lang') || 'zh-CN';

// 翻译函数
function t(key) {
    return translations[currentLang][key] || key;
}

// 切换语言
function switchLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('lang', lang);
    updatePageLanguage();
}

// 更新页面语言
function updatePageLanguage() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (el.tagName === 'INPUT' && el.type !== 'button') {
            el.placeholder = t(key);
        } else {
            el.textContent = t(key);
        }
    });
}

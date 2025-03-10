import xss from 'xss';
import { debounce } from 'lodash-es'
import { Message as MessageEl } from 'element-ui';
const SQL_REGEX = (keywords) =>
  new RegExp(`(?:^|[\\s;=()])(?:${keywords.join('|')})(?=[\\s;]|$)`, 'gi')
// 默认配置
let regEn = /[`~!@$%^&*()+<>?"{},;'[\]·！￥（——）：；“”‘、，|《。》？、【】[\]]/g

const DEFAULT_CONFIG = {
  sqlKeywords: [
    'ALTER', 'CREATE', 'DELETE', 'DROP', 'EXEC', 'INSERT', 'INTO',
    'SELECT', 'UPDATE', 'UNION', 'FROM', 'WHERE', 'TRUNCATE', 'TABLE',
    'DATABASE', 'OR', 'AND', 'NOT', 'EXECUTE', 'DECLARE', 'FETCH', 'OPEN',
    'CLOSE', 'BY', 'HAVING', 'GROUP', 'LIMIT', 'ORDER'
  ],
  debounceTime: 300,
  enableSqlCheck: true,
  enableXssCheck: true,
  enableSpecialStringCheck: false,
  enableNormalStringCheck: false
}

// 创建 XSS 过滤器实例
const createXssFilter = (config) => {
  let filteredItems = []
  const riskTypeMap = {
    tag: '危险标签',
    attribute: '恶意属性',
    sql: 'SQL注入',
    str: '非法字符'
  };
  return {
    filter: new xss.FilterXSS({
      whiteList: {},
      stripIgnoreTag: true,
      onIgnoreTagAttr: (tag, name, value) => {
        filteredItems.push({
          type: 'attribute',
          content: `${name}="${value}"`,
          tagName: tag,
          attrName: name
        });
      },
      onTag: (tag, html, options) => {
        if (options.isClosing) return;
        let constr = html
        //防止在浏览器显示不出来
        let tagmap = {
          '<': '&lt;',
          '>': '&gt;',
          '&': '&amp;',
          '"': '&quot;',
          "'": '&#39;'
        }
        console.log('测试')
        let contents = constr.replace(/[<>&"']/g, (match) => tagmap[match]);
        filteredItems.push({ type: 'tag', content: contents })
      },
    }),
    getFiltered: () => [...filteredItems],
    clear: () => filteredItems = [],
    addFilterItem: (filterItem) => {
      filteredItems.push(filterItem)
    },
    showMsg: () => {
      if (!filteredItems.length) return;
      const riskStats = filteredItems.reduce((acc, item) => {
        acc[item.type] = (acc[item.type] || 0) + 1;
        return acc;
      }, {});
      const messages = filteredItems.map((item, index) => `
        <div class="alert-item" style="margin: 6px 0; padding-left: 24px; position: relative;">
          <span style="position: absolute; left: 0; color: #ff4d4f;">●</span>
          [${index + 1}] 检测到 ${riskTypeMap[item.type]}：
          <span style="opacity: 0.8;">${item.content}</span>
        </div>
      `).join('');

      const statsText = Object.entries(riskStats)
        .map(([type, count]) => `${riskTypeMap[type]} ×${count}`)
        .join('，');
      console.log('messages', messages)
      console.log('statsText', statsText)
      MessageEl({
        type: 'error',
        dangerouslyUseHTMLString: true,
        message: `
         <div style="max-width: 500px;">
            <div style="margin-bottom: 8px; color: #ff4d4f; font-weight: 500;">
              <i class="anticon anticon-warning"></i>
              发现${filteredItems.length}处安全风险（${statsText}）
            </div>
            ${messages}
            <div style="margin-top: 12px; font-size: 0.9em; color: #666;">
              已自动处理危险内容，请不要再次输入
            </div>
          </div>
          `,
        duration: 5000,
        showClose: true
      })
    }
  }
}

// '<script>alert(1)</script><a onclick="attack()">link</a>'"name=SELECT * FROM users"<<>>>><
// "name=SELECT * FROM users"
// UNION ALTER CREATE DELETE DROP EXEC

export const xssFilter = {
  inserted(el, binding) {
    const config = { ...DEFAULT_CONFIG, ...binding.value }
    const { filter, getFiltered, clear, addFilterItem, showMsg } = createXssFilter(config)
    // 创建 SQL 正则
    const sqlRegex = SQL_REGEX(config.sqlKeywords.map(k => k.toUpperCase()))
    // 处理输入的核心方法
    const processInput = debounce((event) => {
      console.log('event', event.target.value)
      console.log('开始')
      console.log('清空前getFiltered', getFiltered())
      clear() // 清空前一次过滤记录
      console.log('清空后getFiltered', getFiltered())
      let value = event.target.value
      console.log('当前value', value)


      // XSS 过滤
      if (config.enableXssCheck) {
        value = filter.process(value)
        console.log('xss过滤后的value', value)
        //有些字符会被浏览器自动编码，需要单独解码一下
        function decodeEntities(encodedString) {
          const textArea = document.createElement('textarea');
          textArea.innerHTML = encodedString;
          return textArea.value;
        }
        value = decodeEntities(value)
        console.log('xss过滤后的filteredItems', getFiltered())
        console.log('xss过滤后的value', value)
      }
      // SQL 过滤
      if (config.enableSqlCheck) {
        console.log('sql过滤之前的value', value)
        value = value.replace(sqlRegex, (match, prefix, keyword) => {
          console.log('match', match)
          console.log('prefix', prefix)
          console.log('keyword', keyword)
          const filtered = match.toUpperCase()
          addFilterItem({
            type: 'sql',
            content: filtered,
            position: event.target.selectionStart
          })
          return ''
        })
        console.log('sql过滤后的filteredItems', getFiltered())
        console.log('sql过滤后的value', value)
      }

      // 对字符串有特殊需求的输入框过滤
      if (config.enableSpecialStringCheck) {
        console.log('特殊字符有特殊需求过滤之前的value', value)
        value = value.replace(regEn, (match, prefix, keyword) => {
          console.log('没有特殊需求的输入框过滤')
          console.log('match', match)
          console.log('prefix', prefix)
          console.log('keyword', keyword)
          addFilterItem({
            type: 'str',
            content: match,
            position: event.target.selectionStart  // 获取输入框当前光标位置,用于记录过滤字符的位置。event.target指向触发事件的输入框元素,selectionStart属性返回光标在文本中的索引位置
          })
          return ''
        })
      }
      // 对字符串没有特殊需求的输入框过滤
      if (config.enableNormalStringCheck) {
        console.log('特殊字符没有特殊需求过滤之前的value', value)
        let regEn = /[`~!@#$%^&*_+<>?"{}:,.\\/;'[\]·！#￥（——）：；“”‘、，|《。》？、【】[\]]/g
        value = value.replace(regEn, (match, prefix, keyword) => {
          console.log('没有特殊需求的输入框过滤')
          console.log('match', match)
          console.log('prefix', prefix)
          console.log('keyword', keyword)
          addFilterItem({
            type: 'str',
            content: match,
            position: event.target.selectionStart  // 获取输入框当前光标位置,用于记录过滤字符的位置。event.target指向触发事件的输入框元素,selectionStart属性返回光标在文本中的索引位置
          })
          return ''
        })
      }
      event.target.value = value;
      showMsg()
    }, config.debounceTime)
    // 保存处理器以便卸载时使用
    el._xssHandler = processInput
    el.addEventListener('input', processInput)
  },
  unbind(el) {
    console.log('卸载')
    el._xssHandler = null
    el.removeEventListener('input', el._xssHandler)
  }
};

const formatContent = (content) => {
  const maxLength = 20;
  return content.length > maxLength
    ? `${content.slice(0, maxLength)}...`
    : content;
};
function generateAlStr(al_SQL) {
  return ''
}

//防止输入框sql关键字注入校验
function sanitizeInput(input) {
  // SQL关键字列表
  let sqlKeywords = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'DROP', 'TABLE', 'CREATE', 'ALTER', 'TRUNCATE', 'EXEC', 'UNION', 'GRANT', 'REVOKE'
    // 添加其他SQL关键字...
  ];

  if (input !== undefined) {
    // 遍历关键字列表，检查输入是否包含关键字
    for (let i = 0; i < sqlKeywords.length; i++) {
      if (input.toUpperCase().includes(sqlKeywords[i])) {
        return false;
      }
    }
  }
  return true;
}

function isNull(strval) {
  if (strval !== '') {
    return false;
  }
  return true;
}

// 判断输入是否包含特殊字符-针对没有特殊要求的输入框
function regularInput(str) {
  let regEn = /[`~!@#$%^&*(-)_+<>?"{}:,.\/;'[\]]/im
  let regCn = /[·！#￥（——）：；“”‘、，|《。》？、【】[\]]/im
  if (regEn.test(str)) {
    return str.replace(regEn, '');
  } else if (regCn.test(str)) {
    return str.replace(regCn, '');
  }
  return str;
}

// 判断输入是否包含特殊字符-针对有特殊要求的输入框，比如时间和允许有下划线的
function regularInputSpecial(str) {
  let regEn = /[`~!@$%^&*()+<>?"{},;'[\]]/im,
    regCn = /[·！￥（——）：；“”‘、，|《。》？、【】[\]]/im;
  if (regEn.test(str) || regCn.test(str)) {
    return true;
  }
}

// 缺陷描述特殊情况
function regularInputSpecialDes(str) {
  let regEn = /[`~!@$%^&*+<>?"{}'[\]]/im,
    regCn = /[·！￥——“”‘、|《。》？、【】[\]]/im;
  if (regEn.test(str) || regCn.test(str)) {
    return true;
  }
}

//正则表达式来检验时间输入框的格式是否为"yyyy-MM-dd hh:mm:ss"
function isValidDate(date) {
  // yyyy-MM-dd
  let regex1 = /^\d{4}-\d{2}-\d{2}$/;
  // hh:mm:ss
  let regex2 = /^\d{2}:\d{2}:\d{2}$/;

  let validDate = true;

  // 检查日期部分
  if (!regex1.test(date.slice(0, 10))) {
    validDate = false;
  }

  // 检查时间部分
  if (!regex2.test(date.slice(11))) {
    validDate = false;
  }

  return validDate;
}

//要校验时间范围的时间格式，你可以使用两个正则表达式，一个用于验证日期时间格式，另一个用于验证时间范围格式。
function isValidTimeRange(timeRange) {
  // yyyy-MM-dd HH:mm:ss
  let regex1 = /^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$/;
  // -
  let regex2 = /^-$/;

  let validTimeRange = true;

  // 分割时间范围
  let [start, end] = timeRange.split('-');

  // 检查开始时间格式
  if (!regex1.test(start)) {
    validTimeRange = false;
  }

  // 检查结束时间格式
  if (!regex2.test(end)) {
    validTimeRange = false;
  }

  // 检查开始时间早于等于结束时间
  let startDate = new Date(start.replace(/-/g, '/'));
  let endDate = new Date(end.replace(/-/g, '/'));
  if (startDate > endDate) {
    validTimeRange = false;
  }

  return validTimeRange;
}

//判断结束时间必须大于开始时间
function checkStartTimeAndEndTime(startTime, endTime) {
  // 将字符串时间转换为 JavaScript Date 对象
  let startDate = new Date(startTime);
  let endDate = new Date(endTime);

  // 使用比较运算符来比较开始时间和结束时间
  if (startDate >= endDate) {
    return false; // 开始时间晚于或等于结束时间，不符合条件
  } else {
    return true; // 开始时间早于结束时间，符合条件
  }
}

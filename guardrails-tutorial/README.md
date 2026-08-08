# Руководство по написанию Guardrails

## Что такое Guardrails?

**Guardrails** (защитные механизмы) — это правила и проверки, которые обеспечивают безопасность, корректность и соответствие требованиям в системах с искусственным интеллектом, особенно в LLM (Large Language Models).

## Основные типы Guardrails

### 1. **Input Validation (Валидация входных данных)**
- Проверка формата ввода
- Блокировка вредоносных запросов
- Ограничение длины ввода
- Фильтрация запрещённых тем

### 2. **Output Validation (Валидация выходных данных)**
- Проверка структуры ответа
- Фильтрация нежелательного контента
- Гарантия соответствия формату
- Проверка фактической точности

### 3. **Content Filters (Фильтры контента)**
- Блокировка токсичного контента
- Предотвращение утечки конфиденциальных данных
- Фильтрация предвзятых высказываний

### 4. **Behavioral Guards (Поведенческие ограничения)**
- Ограничение на выполнение определённых действий
- Контроль доступа к инструментам/API
- Мониторинг аномального поведения

## Примеры реализации

### Пример 1: Простая валидация ввода (Python)

```python
def validate_input(user_input: str) -> bool:
    """Проверяет, безопасен ли ввод пользователя"""
    
    # Проверка длины
    if len(user_input) > 1000:
        return False
    
    # Проверка на SQL-инъекции
    sql_keywords = ['DROP', 'DELETE', 'INSERT', '--', ';']
    if any(keyword in user_input.upper() for keyword in sql_keywords):
        return False
    
    # Проверка на XSS
    xss_patterns = ['<script>', 'javascript:', 'onerror=']
    if any(pattern in user_input.lower() for pattern in xss_patterns):
        return False
    
    return True
```

### Пример 2: Валидация вывода LLM

```python
import re
from typing import Dict, Any

def validate_llm_output(output: str, expected_format: str) -> Dict[str, Any]:
    """Проверяет формат вывода LLM"""
    
    result = {
        'valid': False,
        'errors': [],
        'sanitized_output': output
    }
    
    if expected_format == 'json':
        try:
            import json
            json.loads(output)
            result['valid'] = True
        except json.JSONDecodeError as e:
            result['errors'].append(f'Invalid JSON: {str(e)}')
    
    elif expected_format == 'email':
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, output.strip()):
            result['errors'].append('Invalid email format')
        else:
            result['valid'] = True
    
    elif expected_format == 'phone':
        phone_pattern = r'^\+?[\d\s-\(\)]+$'
        if not re.match(phone_pattern, output.strip()):
            result['errors'].append('Invalid phone format')
        else:
            result['valid'] = True
    
    return result
```

### Пример 3: Content Filter для токсичности

```python
class ContentFilter:
    def __init__(self):
        self.toxic_words = set([
            'оскорбление1', 'оскорбление2',  # замените на реальный список
            # лучше использовать готовые библиотеки типа detoxify
        ])
        
        self.secret_patterns = [
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # кредитные карты
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # emails
        ]
    
    def filter_content(self, text: str) -> tuple[bool, str]:
        """
        Проверяет контент на токсичность и утечку данных
        Returns: (is_safe, filtered_text)
        """
        is_safe = True
        filtered_text = text
        
        # Проверка на токсичные слова
        for word in self.toxic_words:
            if word.lower() in text.lower():
                is_safe = False
                filtered_text = filtered_text.replace(word, '[REDACTED]')
        
        # Проверка на конфиденциальные данные
        import re
        for pattern in self.secret_patterns:
            matches = re.findall(pattern, text)
            if matches:
                is_safe = False
                for match in matches:
                    filtered_text = filtered_text.replace(match, '[REDACTED]')
        
        return is_safe, filtered_text
```

### Пример 4: Использование библиотеки Guardrails AI

```python
# Установка: pip install guardrails-ai

from guardrails import Guard
from guardrails.validators import ValidLength, EndWith

# Определение рейлса с валидаторами
guard = Guard().use(
    ValidLength(min=10, max=100, on_fail='fix'),
    EndWith('.', on_fail='fix')
)

# Применение к выводу LLM
validated_output = guard(
    llm_output="Это пример текста.",
    prompt_params={}
)
```

### Пример 5: Комплексный Guard для API

```python
from functools import wraps
from typing import Callable
import time

class APISecurityGuard:
    def __init__(self, rate_limit: int = 100, window_seconds: int = 60):
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.request_history = {}
    
    def rate_limit_check(self, user_id: str) -> bool:
        """Проверка rate limiting"""
        current_time = time.time()
        
        if user_id not in self.request_history:
            self.request_history[user_id] = []
        
        # Очистка старых запросов
        self.request_history[user_id] = [
            req_time for req_time in self.request_history[user_id]
            if current_time - req_time < self.window_seconds
        ]
        
        if len(self.request_history[user_id]) >= self.rate_limit:
            return False
        
        self.request_history[user_id].append(current_time)
        return True
    
    def secure_endpoint(self, func: Callable) -> Callable:
        """Декоратор для защиты endpoint"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = kwargs.get('user_id', 'anonymous')
            
            # Rate limiting
            if not self.rate_limit_check(user_id):
                return {'error': 'Rate limit exceeded', 'status': 429}
            
            # Input validation
            input_data = kwargs.get('input', '')
            if not self.validate_input(input_data):
                return {'error': 'Invalid input', 'status': 400}
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Output validation
            if not self.validate_output(result):
                return {'error': 'Invalid output', 'status': 500}
            
            return result
        
        return wrapper
    
    def validate_input(self, data: str) -> bool:
        # Реализация валидации ввода
        return len(data) <= 1000 and not self.contains_malicious_content(data)
    
    def validate_output(self, data: dict) -> bool:
        # Реализация валидации вывода
        return 'error' not in data or data.get('status', 200) < 400
    
    def contains_malicious_content(self, text: str) -> bool:
        # Проверка на вредоносный контент
        dangerous_patterns = ['<script>', 'DROP TABLE', '../']
        return any(pattern in text for pattern in dangerous_patterns)


# Использование
guard = APISecurityGuard(rate_limit=10, window_seconds=60)

@guard.secure_endpoint
def process_request(user_id: str, input: str):
    return {'result': f'Processed: {input}', 'status': 200}
```

## Лучшие практики

### 1. **Defense in Depth (Многоуровневая защита)**
- Не полагайтесь на один guardrail
- Используйте несколько уровней проверки
- Сочетайте превентивные и реактивные меры

### 2. **Fail Secure (Безопасный отказ)**
- При ошибке валидации блокируйте запрос
- Логируйте инциденты для анализа
- Не раскрывайте детали ошибок пользователю

### 3. **Regular Updates (Регулярное обновление)**
- Обновляйте списки запрещённых слов/паттернов
- Анализируйте новые векторы атак
- Тестируйте guardrails на обход

### 4. **Performance Consideration (Производительность)**
- Кэшируйте результаты проверок
- Используйте эффективные алгоритмы
- Балансируйте между безопасностью и скоростью

### 5. **Testing (Тестирование)**
```python
def test_guardrails():
    """Пример тестов для guardrails"""
    
    # Тест валидации ввода
    assert validate_input("нормальный текст") == True
    assert validate_input("<script>alert('xss')</script>") == False
    assert validate_input("DROP TABLE users;") == False
    
    # Тест фильтра контента
    filter = ContentFilter()
    is_safe, filtered = filter.filter_content("нормальный текст")
    assert is_safe == True
    
    # Тест rate limiting
    guard = APISecurityGuard(rate_limit=3, window_seconds=60)
    assert guard.rate_limit_check("user1") == True
    assert guard.rate_limit_check("user1") == True
    assert guard.rate_limit_check("user1") == True
    assert guard.rate_limit_check("user1") == False  # Превышен лимит
```

## Полезные инструменты и библиотеки

1. **Guardrails AI** - Фреймворк для валидации вывода LLM
2. **Rebuff** - Защита от prompt injection
3. **Detoxify** - Библиотека для обнаружения токсичного контента
4. **Presidio** - Microsoft библиотека для обнаружения PII
5. **LangChain Guards** - Интеграция guardrails в LangChain

## Ресурсы для изучения

- [Guardrails AI Documentation](https://docs.guardrails.ai/)
- [OWASP Top 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Microsoft Presidio](https://microsoft.github.io/presidio/)
- [LangChain Security](https://python.langchain.com/docs/security)

## Заключение

Написание эффективных guardrails требует:
- Понимания угроз и уязвимостей
- Многоуровневого подхода к безопасности
- Регулярного тестирования и обновления
- Баланса между безопасностью и удобством использования

Начните с простых проверок и постепенно добавляйте более сложные механизмы защиты по мере роста требований вашего приложения.

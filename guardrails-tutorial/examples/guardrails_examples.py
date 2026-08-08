"""
Практические примеры реализации Guardrails

Этот файл содержит рабочие примеры различных типов guardrails,
которые вы можете использовать в своих проектах.
"""

import re
import json
import time
from typing import Dict, Any, List, Tuple, Optional
from functools import wraps
from dataclasses import dataclass


# ============================================================================
# Пример 1: Базовая валидация ввода
# ============================================================================

def validate_input_basic(user_input: str, max_length: int = 1000) -> Tuple[bool, List[str]]:
    """
    Базовая проверка пользовательского ввода
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_errors)
    """
    errors = []
    
    # Проверка на пустоту
    if not user_input or not user_input.strip():
        errors.append("Input cannot be empty")
        return False, errors
    
    # Проверка длины
    if len(user_input) > max_length:
        errors.append(f"Input exceeds maximum length of {max_length}")
    
    # Проверка на SQL-инъекции
    sql_patterns = [
        r'(\bDROP\b.*\bTABLE\b)',
        r'(\bDELETE\b.*\bFROM\b)',
        r'(\bINSERT\b.*\bINTO\b)',
        r'(\bUPDATE\b.*\bSET\b)',
        r'(--)',
        r';\s*$',
        r"'\s*OR\s*'1'\s*=\s*'1",
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            errors.append("Potential SQL injection detected")
            break
    
    # Проверка на XSS
    xss_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onload\s*=',
        r'<iframe',
        r'<object',
        r'<embed',
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            errors.append("Potential XSS attack detected")
            break
    
    # Проверка на path traversal
    if '../' in user_input or '..\\' in user_input:
        errors.append("Potential path traversal detected")
    
    is_valid = len(errors) == 0
    return is_valid, errors


# ============================================================================
# Пример 2: Валидация формата вывода
# ============================================================================

@dataclass
class ValidationResult:
    valid: bool
    errors: List[str]
    sanitized_output: str
    metadata: Dict[str, Any]


def validate_json_output(output: str) -> ValidationResult:
    """Проверяет, что вывод является валидным JSON"""
    errors = []
    
    try:
        parsed = json.loads(output)
        return ValidationResult(
            valid=True,
            errors=[],
            sanitized_output=output,
            metadata={'parsed_data': parsed}
        )
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {str(e)}")
        return ValidationResult(
            valid=False,
            errors=errors,
            sanitized_output=output,
            metadata={}
        )


def validate_email_output(output: str) -> ValidationResult:
    """Проверяет формат email"""
    errors = []
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    
    cleaned = output.strip()
    if not re.match(email_pattern, cleaned):
        errors.append("Invalid email format")
    
    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        sanitized_output=cleaned,
        metadata={}
    )


def validate_phone_output(output: str, country_code: str = 'US') -> ValidationResult:
    """Проверяет формат телефонного номера"""
    errors = []
    
    # Разные паттерны для разных стран
    patterns = {
        'US': r'^\+?1?\s*\d{3}\s*\d{3}\s*\d{4}$',
        'RU': r'^\+?7\s*\d{3}\s*\d{3}\s*\d{2}\s*\d{2}$',
        'INTL': r'^\+\d{1,3}\s*\d{6,14}$',
    }
    
    pattern = patterns.get(country_code, patterns['INTL'])
    cleaned = output.strip()
    
    if not re.match(pattern, cleaned):
        errors.append(f"Invalid phone format for {country_code}")
    
    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        sanitized_output=cleaned,
        metadata={'country_code': country_code}
    )


# ============================================================================
# Пример 3: Фильтр контента
# ============================================================================

class ContentFilter:
    """
    Многоуровневый фильтр контента для обнаружения:
    - Токсичных высказываний
    - Конфиденциальных данных (PII)
    - Запрещённых тем
    """
    
    def __init__(self):
        # Примеры токсичных слов (в реальном проекте используйте готовые решения)
        self.toxic_words = {
            'spam': ['спам', 'раскрутка', 'накрутка'],
            'hate': ['ненависть', 'дискриминация'],
            # Добавьте больше категорий и слов
        }
        
        # Паттерны для обнаружения PII (Personally Identifiable Information)
        self.pii_patterns = {
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone_ru': r'\b(?:\+7|8)\s*\d{3}\s*\d{3}\s*\d{2}\s*\d{2}\b',
            'passport_ru': r'\b\d{4}\s*\d{6}\b',
            'snils': r'\b\d{3}-\d{3}-\d{3}\s*\d{2}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        }
        
        # Запрещённые темы
        self.forbidden_topics = [
            'как создать бомбу',
            'как взломать',
            'наркотики',
            # Добавьте больше тем
        ]
    
    def filter_content(self, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Комплексная проверка контента
        
        Returns:
            Tuple[bool, str, Dict]: (is_safe, filtered_text, metadata)
        """
        is_safe = True
        filtered_text = text
        metadata = {
            'issues_found': [],
            'pii_detected': [],
            'toxicity_score': 0.0,
        }
        
        # 1. Проверка на токсичность
        toxicity_count = 0
        for category, words in self.toxic_words.items():
            for word in words:
                if word.lower() in text.lower():
                    toxicity_count += 1
                    filtered_text = re.sub(
                        re.escape(word), 
                        '[REDACTED]', 
                        filtered_text,
                        flags=re.IGNORECASE
                    )
        
        if toxicity_count > 0:
            is_safe = False
            metadata['issues_found'].append('toxic_content')
            metadata['toxicity_score'] = min(toxicity_count / 10, 1.0)
        
        # 2. Проверка на PII
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                is_safe = False
                metadata['pii_detected'].append({
                    'type': pii_type,
                    'count': len(matches)
                })
                for match in matches:
                    filtered_text = filtered_text.replace(match, f'[{pii_type.upper()}]')
        
        # 3. Проверка на запрещённые темы
        for topic in self.forbidden_topics:
            if topic.lower() in text.lower():
                is_safe = False
                metadata['issues_found'].append('forbidden_topic')
                break
        
        return is_safe, filtered_text, metadata


# ============================================================================
# Пример 4: Rate Limiter
# ============================================================================

class RateLimiter:
    """
    Ограничитель частоты запросов (Rate Limiting)
    Реализует скользящее окно для контроля количества запросов
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_history: Dict[str, List[float]] = {}
    
    def is_allowed(self, user_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Проверяет, разрешён ли запрос для пользователя
        
        Returns:
            Tuple[bool, Dict]: (is_allowed, metadata)
        """
        current_time = time.time()
        
        if user_id not in self.request_history:
            self.request_history[user_id] = []
        
        # Очищаем старые запросы за пределами окна
        self.request_history[user_id] = [
            req_time for req_time in self.request_history[user_id]
            if current_time - req_time < self.window_seconds
        ]
        
        # Проверяем лимит
        current_count = len(self.request_history[user_id])
        is_allowed = current_count < self.max_requests
        
        metadata = {
            'current_count': current_count,
            'max_requests': self.max_requests,
            'window_seconds': self.window_seconds,
            'remaining': max(0, self.max_requests - current_count - 1) if is_allowed else 0,
            'retry_after': self.window_seconds if not is_allowed else 0,
        }
        
        if is_allowed:
            self.request_history[user_id].append(current_time)
        
        return is_allowed, metadata
    
    def reset(self, user_id: str):
        """Сбрасывает историю запросов для пользователя"""
        if user_id in self.request_history:
            del self.request_history[user_id]


# ============================================================================
# Пример 5: Декоратор для защиты API endpoints
# ============================================================================

class APIGuard:
    """
    Комплексный защитник для API endpoints
    Объединяет валидацию ввода, rate limiting и фильтрацию вывода
    """
    
    def __init__(
        self,
        rate_limit: int = 100,
        rate_window: int = 60,
        max_input_length: int = 1000
    ):
        self.rate_limiter = RateLimiter(rate_limit, rate_window)
        self.content_filter = ContentFilter()
        self.max_input_length = max_input_length
    
    def protect_endpoint(self, func):
        """
        Декоратор для защиты функции endpoint
        
        Использование:
            api_guard = APIGuard()
            
            @api_guard.protect_endpoint
            def my_endpoint(user_id: str, input: str):
                return {'result': process(input)}
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Извлекаем параметры
            user_id = kwargs.get('user_id', args[0] if args else 'anonymous')
            input_data = kwargs.get('input', args[1] if len(args) > 1 else '')
            
            # 1. Rate limiting
            rate_allowed, rate_metadata = self.rate_limiter.is_allowed(user_id)
            if not rate_allowed:
                return {
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'status': 429,
                    'retry_after': rate_metadata['retry_after']
                }
            
            # 2. Валидация ввода
            if isinstance(input_data, str):
                is_valid, errors = validate_input_basic(
                    input_data, 
                    max_length=self.max_input_length
                )
                if not is_valid:
                    return {
                        'success': False,
                        'error': 'Invalid input',
                        'details': errors,
                        'status': 400
                    }
                
                # 3. Фильтрация контента
                is_safe, filtered_input, filter_metadata = self.content_filter.filter_content(input_data)
                if not is_safe:
                    return {
                        'success': False,
                        'error': 'Content policy violation',
                        'details': filter_metadata['issues_found'],
                        'status': 403
                    }
                
                # Обновляем input на отфильтрованную версию
                kwargs['input'] = filtered_input
            
            # 4. Выполнение функции
            try:
                result = func(*args, **kwargs)
                
                # 5. Валидация вывода (если это dict с полем 'output')
                if isinstance(result, dict) and 'output' in result:
                    is_safe, filtered_output, _ = self.content_filter.filter_content(
                        str(result['output'])
                    )
                    if not is_safe:
                        result['output'] = '[CONTENT FILTERED]'
                        result['warning'] = 'Output contained policy violations'
                
                result['success'] = True
                result['status'] = 200
                return result
                
            except Exception as e:
                return {
                    'success': False,
                    'error': 'Internal server error',
                    'details': str(e),
                    'status': 500
                }
        
        return wrapper


# ============================================================================
# Пример 6: Валидатор структуры ответа LLM
# ============================================================================

class LLMResponseValidator:
    """
    Валидатор для ответов языковых моделей
    Проверяет структуру, формат и содержание ответа
    """
    
    def __init__(self, expected_fields: Optional[List[str]] = None):
        self.expected_fields = expected_fields or []
    
    def validate_structure(self, response: Dict[str, Any]) -> ValidationResult:
        """Проверяет наличие обязательных полей"""
        errors = []
        
        for field in self.expected_fields:
            if field not in response:
                errors.append(f"Missing required field: {field}")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            sanitized_output=json.dumps(response),
            metadata={'fields_present': list(response.keys())}
        )
    
    def validate_no_hallucination(
        self, 
        response: str, 
        context: str,
        confidence_threshold: float = 0.8
    ) -> ValidationResult:
        """
        Эвристическая проверка на галлюцинации
        (в реальности используйте более сложные методы)
        """
        errors = []
        
        # Простая проверка: если ответ слишком короткий для сложного вопроса
        if len(context) > 500 and len(response) < 50:
            errors.append("Response may be too brief for the given context")
        
        # Проверка на неуверенные формулировки
        uncertainty_phrases = [
            'возможно', 'может быть', 'не уверен', 
            'probably', 'maybe', 'i think', 'might be'
        ]
        
        uncertainty_count = sum(
            1 for phrase in uncertainty_phrases 
            if phrase.lower() in response.lower()
        )
        
        if uncertainty_count > 3:
            errors.append("Response contains multiple uncertainty markers")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            sanitized_output=response,
            metadata={'uncertainty_markers': uncertainty_count}
        )
    
    def validate_consistency(
        self, 
        responses: List[str], 
        tolerance: float = 0.9
    ) -> ValidationResult:
        """
        Проверяет согласованность нескольких ответов на один вопрос
        """
        errors = []
        
        if len(responses) < 2:
            return ValidationResult(
                valid=True,
                errors=[],
                sanitized_output='',
                metadata={'note': 'Need at least 2 responses to check consistency'}
            )
        
        # Простая эвристика: проверка на общие ключевые слова
        words_sets = [set(r.lower().split()) for r in responses]
        
        # Проверяем пересечение между всеми парами
        for i in range(len(words_sets)):
            for j in range(i + 1, len(words_sets)):
                intersection = len(words_sets[i] & words_sets[j])
                union = len(words_sets[i] | words_sets[j])
                similarity = intersection / union if union > 0 else 0
                
                if similarity < tolerance:
                    errors.append(
                        f"Low consistency between responses {i+1} and {j+1}: "
                        f"similarity={similarity:.2f}"
                    )
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            sanitized_output='',
            metadata={'responses_compared': len(responses)}
        )


# ============================================================================
# Примеры использования
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Пример 1: Валидация ввода")
    print("=" * 60)
    
    test_inputs = [
        "Нормальный пользовательский ввод",
        "<script>alert('xss')</script>",
        "DROP TABLE users; --",
        "../../../etc/passwd",
        "",
        "A" * 2000,
    ]
    
    for test_input in test_inputs:
        is_valid, errors = validate_input_basic(test_input)
        print(f"\nInput: {test_input[:50]}...")
        print(f"Valid: {is_valid}")
        if errors:
            print(f"Errors: {errors}")
    
    print("\n" + "=" * 60)
    print("Пример 2: Валидация форматов")
    print("=" * 60)
    
    # JSON
    json_result = validate_json_output('{"name": "John", "age": 30}')
    print(f"\nJSON Validation: {json_result.valid}")
    
    # Email
    email_result = validate_email_output('test@example.com')
    print(f"Email Validation: {email_result.valid}")
    
    # Phone
    phone_result = validate_phone_output('+7 999 123 4567', country_code='RU')
    print(f"Phone Validation: {phone_result.valid}")
    
    print("\n" + "=" * 60)
    print("Пример 3: Фильтр контента")
    print("=" * 60)
    
    filter = ContentFilter()
    test_texts = [
        "Мой email: test@example.com, телефон: +7 999 123 4567",
        "Нормальный текст без нарушений",
        "Кредитная карта: 1234 5678 9012 3456",
    ]
    
    for text in test_texts:
        is_safe, filtered, metadata = filter.filter_content(text)
        print(f"\nOriginal: {text}")
        print(f"Safe: {is_safe}")
        print(f"Filtered: {filtered}")
        print(f"Metadata: {metadata}")
    
    print("\n" + "=" * 60)
    print("Пример 4: Rate Limiter")
    print("=" * 60)
    
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    user_id = "test_user"
    
    for i in range(7):
        allowed, metadata = limiter.is_allowed(user_id)
        print(f"Request {i+1}: Allowed={allowed}, Remaining={metadata['remaining']}")
    
    print("\n" + "=" * 60)
    print("Пример 5: API Guard (демонстрация)")
    print("=" * 60)
    
    api_guard = APIGuard(rate_limit=10, rate_window=60)
    
    @api_guard.protect_endpoint
    def sample_endpoint(user_id: str, input: str):
        return {'output': f'Processed: {input}'}
    
    # Тестовые вызовы
    test_cases = [
        {'user_id': 'user1', 'input': 'нормальный ввод'},
        {'user_id': 'user1', 'input': '<script>bad</script>'},
        {'user_id': 'user1', 'input': 'test@example.com'},
    ]
    
    for i, params in enumerate(test_cases):
        result = sample_endpoint(**params)
        print(f"\nTest {i+1}: {result}")
    
    print("\n" + "=" * 60)
    print("Пример 6: LLM Response Validator")
    print("=" * 60)
    
    validator = LLMResponseValidator(expected_fields=['answer', 'confidence'])
    
    # Проверка структуры
    response1 = {'answer': 'Paris', 'confidence': 0.95}
    result1 = validator.validate_structure(response1)
    print(f"\nStructure validation: {result1.valid}")
    
    # Проверка на галлюцинации
    response2 = "Я думаю, возможно, может быть, это где-то там..."
    result2 = validator.validate_no_hallucination(response2, "Длинный контекст..." * 100)
    print(f"Hallucination check: {result2.valid}")
    if result2.errors:
        print(f"Warnings: {result2.errors}")
    
    # Проверка согласованности
    responses = [
        "Париж - столица Франции",
        "Столицей Франции является Париж",
        "Париж находится во Франции",
    ]
    result3 = validator.validate_consistency(responses)
    print(f"\nConsistency check: {result3.valid}")
    
    print("\n" + "=" * 60)
    print("Все примеры завершены!")
    print("=" * 60)

"""
Тесты для Guardrails примеров

Запуск: pytest tests/test_guardrails.py -v
Или: python -m pytest tests/test_guardrails.py -v
"""

import pytest
import sys
import os

# Добавляем путь к примерам
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'examples'))

from guardrails_examples import (
    validate_input_basic,
    validate_json_output,
    validate_email_output,
    validate_phone_output,
    ContentFilter,
    RateLimiter,
    LLMResponseValidator,
    ValidationResult,
)


class TestInputValidation:
    """Тесты для базовой валидации ввода"""
    
    def test_valid_input(self):
        """Проверка корректного ввода"""
        is_valid, errors = validate_input_basic("Нормальный текст")
        assert is_valid is True
        assert len(errors) == 0
    
    def test_empty_input(self):
        """Проверка пустого ввода"""
        is_valid, errors = validate_input_basic("")
        assert is_valid is False
        assert "Input cannot be empty" in errors
    
    def test_whitespace_only_input(self):
        """Проверка ввода только с пробелами"""
        is_valid, errors = validate_input_basic("   \t\n")
        assert is_valid is False
    
    def test_exceeds_max_length(self):
        """Проверка превышения максимальной длины"""
        long_input = "A" * 2000
        is_valid, errors = validate_input_basic(long_input, max_length=1000)
        assert is_valid is False
        assert any("exceeds maximum length" in error for error in errors)
    
    def test_sql_injection_drop(self):
        """Обнаружение SQL-инъекции DROP TABLE"""
        is_valid, errors = validate_input_basic("DROP TABLE users;")
        assert is_valid is False
        assert any("SQL injection" in error for error in errors)
    
    def test_sql_injection_delete(self):
        """Обнаружение SQL-инъекции DELETE"""
        is_valid, errors = validate_input_basic("DELETE FROM users WHERE 1=1")
        assert is_valid is False
    
    def test_sql_injection_comment(self):
        """Обнаружение SQL-комментария"""
        is_valid, errors = validate_input_basic("admin' --")
        assert is_valid is False
    
    def test_xss_script_tag(self):
        """Обнаружение XSS через script тег"""
        is_valid, errors = validate_input_basic("<script>alert('xss')</script>")
        assert is_valid is False
        assert any("XSS" in error for error in errors)
    
    def test_xss_javascript_protocol(self):
        """Обнаружение XSS через javascript: протокол"""
        is_valid, errors = validate_input_basic("javascript:alert(1)")
        assert is_valid is False
    
    def test_xss_event_handler(self):
        """Обнаружение XSS через обработчик событий"""
        is_valid, errors = validate_input_basic('<img onerror="alert(1)">')
        assert is_valid is False
    
    def test_path_traversal_unix(self):
        """Обнаружение path traversal (Unix)"""
        is_valid, errors = validate_input_basic("../../../etc/passwd")
        assert is_valid is False
        assert any("path traversal" in error for error in errors)
    
    def test_path_traversal_windows(self):
        """Обнаружение path traversal (Windows)"""
        is_valid, errors = validate_input_basic("..\\..\\windows\\system32")
        assert is_valid is False
    
    def test_combined_attacks(self):
        """Проверка нескольких атак одновременно"""
        malicious_input = "<script>DROP TABLE users; --</script>"
        is_valid, errors = validate_input_basic(malicious_input)
        assert is_valid is False
        # Должна быть обнаружена хотя бы одна атака
        assert len(errors) > 0


class TestFormatValidation:
    """Тесты для валидации форматов"""
    
    def test_valid_json(self):
        """Проверка валидного JSON"""
        result = validate_json_output('{"name": "John", "age": 30}')
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_invalid_json(self):
        """Проверка невалидного JSON"""
        result = validate_json_output('{name: "John"}')  #缺少 кавычек
        assert result.valid is False
        assert len(result.errors) > 0
    
    def test_valid_json_array(self):
        """Проверка валидного JSON массива"""
        result = validate_json_output('[1, 2, 3, 4]')
        assert result.valid is True
    
    def test_valid_email_simple(self):
        """Проверка простого email"""
        result = validate_email_output('test@example.com')
        assert result.valid is True
    
    def test_valid_email_with_dots(self):
        """Проверка email с точками"""
        result = validate_email_output('john.doe@company.co.uk')
        assert result.valid is True
    
    def test_invalid_email_no_at(self):
        """Проверка email без @"""
        result = validate_email_output('testexample.com')
        assert result.valid is False
    
    def test_invalid_email_no_domain(self):
        """Проверка email без домена"""
        result = validate_email_output('test@')
        assert result.valid is False
    
    def test_valid_phone_us(self):
        """Проверка телефона США"""
        result = validate_phone_output('+1 555 123 4567', country_code='US')
        assert result.valid is True
    
    def test_valid_phone_ru(self):
        """Проверка телефона России"""
        result = validate_phone_output('+7 999 123 4567', country_code='RU')
        assert result.valid is True
    
    def test_invalid_phone(self):
        """Проверка невалидного телефона"""
        result = validate_phone_output('123', country_code='US')
        assert result.valid is False


class TestContentFilter:
    """Тесты для фильтра контента"""
    
    def test_clean_content(self):
        """Проверка чистого контента"""
        filter = ContentFilter()
        is_safe, filtered, metadata = filter.filter_content("Нормальный текст")
        assert is_safe is True
        assert filtered == "Нормальный текст"
        assert len(metadata['issues_found']) == 0
    
    def test_email_detection(self):
        """Обнаружение email в тексте"""
        filter = ContentFilter()
        text = "Мой контакт: test@example.com"
        is_safe, filtered, metadata = filter.filter_content(text)
        assert is_safe is False
        assert '[EMAIL]' in filtered
        assert any(p['type'] == 'email' for p in metadata['pii_detected'])
    
    def test_credit_card_detection(self):
        """Обнаружение кредитной карты"""
        filter = ContentFilter()
        text = "Карта: 1234 5678 9012 3456"
        is_safe, filtered, metadata = filter.filter_content(text)
        assert is_safe is False
        assert '[CREDIT_CARD]' in filtered
    
    def test_phone_ru_detection(self):
        """Обнаружение российского телефона"""
        filter = ContentFilter()
        text = "Звоните: +7 999 123 4567"
        is_safe, filtered, metadata = filter.filter_content(text)
        assert is_safe is False
        assert '[PHONE_RU]' in filtered or '[REDACTED]' in filtered
    
    def test_ip_address_detection(self):
        """Обнаружение IP адреса"""
        filter = ContentFilter()
        text = "IP адрес: 192.168.1.1"
        is_safe, filtered, metadata = filter.filter_content(text)
        assert is_safe is False
        assert '[IP_ADDRESS]' in filtered
    
    def test_multiple_pii(self):
        """Обнаружение нескольких PII"""
        filter = ContentFilter()
        text = "Email: test@example.com, карта: 1234 5678 9012 3456"
        is_safe, filtered, metadata = filter.filter_content(text)
        assert is_safe is False
        assert len(metadata['pii_detected']) >= 2
    
    def test_toxic_word_redaction(self):
        """Замена токсичных слов"""
        filter = ContentFilter()
        text = "Это спам предложение"
        is_safe, filtered, metadata = filter.filter_content(text)
        # Спам считается токсичным контентом
        assert '[REDACTED]' in filtered or not is_safe


class TestRateLimiter:
    """Тесты для ограничителя частоты запросов"""
    
    def test_first_request_allowed(self):
        """Первый запрос должен быть разрешён"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        allowed, metadata = limiter.is_allowed("user1")
        assert allowed is True
        assert metadata['remaining'] == 4
    
    def test_within_limit(self):
        """Запросы в пределах лимита"""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        
        for i in range(3):
            allowed, metadata = limiter.is_allowed("user2")
            assert allowed is True
    
    def test_exceeds_limit(self):
        """Превышение лимита"""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        
        # Первые два запроса
        limiter.is_allowed("user3")
        limiter.is_allowed("user3")
        
        # Третий должен быть отклонён
        allowed, metadata = limiter.is_allowed("user3")
        assert allowed is False
        assert metadata['remaining'] == 0
    
    def test_different_users_independent(self):
        """Разные пользователи независимы"""
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        
        # Пользователь 1 исчерпывает лимит
        limiter.is_allowed("user_a")
        allowed_a, _ = limiter.is_allowed("user_a")
        assert allowed_a is False
        
        # Пользователь 2 ещё имеет лимит
        allowed_b, _ = limiter.is_allowed("user_b")
        assert allowed_b is True
    
    def test_metadata_accuracy(self):
        """Точность метаданных"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        allowed, metadata = limiter.is_allowed("user4")
        assert metadata['max_requests'] == 5
        assert metadata['window_seconds'] == 60
        assert metadata['current_count'] == 1
        assert metadata['remaining'] == 4


class TestLLMResponseValidator:
    """Тесты для валидатора ответов LLM"""
    
    def test_structure_valid(self):
        """Валидная структура"""
        validator = LLMResponseValidator(expected_fields=['answer', 'confidence'])
        response = {'answer': 'Paris', 'confidence': 0.95, 'source': 'wiki'}
        result = validator.validate_structure(response)
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_structure_missing_field(self):
        """Отсутствующее поле"""
        validator = LLMResponseValidator(expected_fields=['answer', 'confidence'])
        response = {'answer': 'Paris'}  # нет confidence
        result = validator.validate_structure(response)
        assert result.valid is False
        assert any("Missing required field" in error for error in result.errors)
    
    def test_hallucination_short_response(self):
        """Обнаружение галлюцинации - короткий ответ"""
        validator = LLMResponseValidator()
        long_context = "Длинный контекст... " * 100
        short_response = "Не знаю"
        result = validator.validate_no_hallucination(short_response, long_context)
        assert result.valid is False
        assert any("too brief" in error.lower() for error in result.errors)
    
    def test_hallucination_uncertainty(self):
        """Обнаружение галлюцинации - неуверенность"""
        validator = LLMResponseValidator()
        uncertain_response = "Возможно, может быть, я думаю, не уверен, наверное"
        result = validator.validate_no_hallucination(uncertain_response, "Короткий контекст")
        assert result.valid is False
        assert any("uncertainty" in error.lower() for error in result.errors)
    
    def test_consistency_high_similarity(self):
        """Высокая согласованность ответов"""
        validator = LLMResponseValidator()
        responses = [
            "Париж - столица Франции",
            "Столица Франции - Париж",
        ]
        result = validator.validate_consistency(responses, tolerance=0.5)
        # При низкой толерантности должно пройти
        assert result.valid is True or len(result.errors) == 0
    
    def test_consistency_low_similarity(self):
        """Низкая согласованность ответов"""
        validator = LLMResponseValidator()
        responses = [
            "Париж - столица Франции",
            "Берлин - столица Германии",
            "Токио - столица Японии",
        ]
        result = validator.validate_consistency(responses, tolerance=0.9)
        # При высокой толерантности должно найти несоответствия
        assert len(result.errors) > 0


class TestValidationResult:
    """Тесты для структуры ValidationResult"""
    
    def test_result_creation(self):
        """Создание результата валидации"""
        result = ValidationResult(
            valid=True,
            errors=[],
            sanitized_output="test",
            metadata={'key': 'value'}
        )
        assert result.valid is True
        assert len(result.errors) == 0
        assert result.sanitized_output == "test"
        assert result.metadata['key'] == 'value'
    
    def test_result_with_errors(self):
        """Результат с ошибками"""
        result = ValidationResult(
            valid=False,
            errors=['Error 1', 'Error 2'],
            sanitized_output="",
            metadata={}
        )
        assert result.valid is False
        assert len(result.errors) == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

from pyicloud.models.errors import ServiceErrorsModel


def test_service_errors_model_coerces_non_string_message() -> None:
    payload = {
        "service_errors": [
            {
                "code": 1,
                "message": 1,
            }
        ],
        "has_error": True,
    }

    result = ServiceErrorsModel.model_validate(payload)

    assert len(result.service_errors) == 1
    assert result.service_errors[0].message == "1"

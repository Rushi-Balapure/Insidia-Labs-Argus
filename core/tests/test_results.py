"""The result contract: execution and policy are separate."""

from insidia.results import (
    CANCELLED,
    COMPLETE,
    ERROR,
    INFO,
    LIMITED,
    NOT_APPLICABLE,
    CheckRecord,
    aggregate,
    exit_for,
    legacy_passed,
)


def test_a_finished_scan_with_no_findings_passes() -> None:
    status, verdict = aggregate([CheckRecord("app", "web.ssti", "insidia", COMPLETE)])
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)
    assert legacy_passed(status, verdict) is True


def test_a_finished_scan_with_a_finding_fails() -> None:
    status, verdict = aggregate(
        [CheckRecord("app", "web.ssti", "insidia", COMPLETE, finding_count=1)]
    )
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "fail", 1)
    assert legacy_passed(status, verdict) is False


def test_a_failed_engine_beside_a_clean_one_is_incomplete() -> None:
    records = [
        CheckRecord("app", "ai.data_leakage", "insidia", COMPLETE),
        CheckRecord("app", "ai.data_leakage", "garak", ERROR, "report missing"),
    ]
    status, verdict = aggregate(records)
    assert status == "incomplete"
    assert verdict == "inconclusive"
    assert exit_for(status, verdict) == 2
    assert legacy_passed(status, verdict) is False


def test_findings_survive_a_failed_engine() -> None:
    records = [
        CheckRecord("app", "ai.data_leakage", "insidia", COMPLETE, finding_count=1),
        CheckRecord("app", "ai.data_leakage", "garak", ERROR, "report missing"),
    ]
    status, verdict = aggregate(records)
    assert status == "incomplete"
    assert verdict == "fail"
    assert exit_for(status, verdict) == 1


def test_no_applicable_check_is_inconclusive() -> None:
    status, verdict = aggregate([CheckRecord("app", "chat", "", NOT_APPLICABLE, "no controls")])
    assert (status, verdict, exit_for(status, verdict)) == ("incomplete", "inconclusive", 2)


def test_info_alone_is_inconclusive() -> None:
    status, verdict = aggregate([CheckRecord("app", "infra.cve", "insidia", INFO)])
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "inconclusive", 2)
    assert legacy_passed(status, verdict) is False


def test_info_beside_a_finished_pass_stays_a_pass() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "infra.cve", "insidia", INFO),
    ]
    status, verdict = aggregate(records)
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)


def test_a_finding_still_fails_beside_info() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE, finding_count=1),
        CheckRecord("app", "infra.cve", "insidia", INFO),
    ]
    status, verdict = aggregate(records)
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "fail", 1)


def test_cancellation_exits_130() -> None:
    status, verdict = aggregate([CheckRecord("app", "web.ssti", "insidia", CANCELLED)])
    assert exit_for(status, verdict) == 130


def test_a_pass_that_includes_a_limited_record_is_low_assurance() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "web.ssti", "zap", LIMITED, "zap sent one request"),
    ]
    result = aggregate(records)
    status, verdict = result
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)
    assert legacy_passed(status, verdict) is True
    assert result.low_assurance is True
    assert result.assurance_reason == "zap sent one request"


def test_a_pass_with_only_complete_records_is_not_low_assurance() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "web.headers", "insidia", COMPLETE),
    ]
    result = aggregate(records)
    status, verdict = result
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)
    assert result.low_assurance is False
    assert result.assurance_reason == ""


def test_a_limited_record_outside_a_passing_check_does_not_lower_the_run() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "web.xss", "zap", LIMITED, "zap sent one request"),
    ]
    result = aggregate(records)
    status, verdict = result
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)
    assert result.low_assurance is False
    assert result.assurance_reason == ""


def test_a_limited_record_alone_is_not_a_low_assurance_pass() -> None:
    result = aggregate([CheckRecord("app", "web.ssti", "zap", LIMITED, "zap sent one request")])
    status, verdict = result
    assert verdict != "pass"
    assert legacy_passed(status, verdict) is False
    assert exit_for(status, verdict) != 0
    assert result.low_assurance is False


def test_a_finding_beside_a_limited_record_stays_a_failure() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE, finding_count=1),
        CheckRecord("app", "web.ssti", "zap", LIMITED, "zap sent one request"),
    ]
    result = aggregate(records)
    status, verdict = result
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "fail", 1)
    assert result.low_assurance is False


def test_limited_reasons_in_one_pass_stay_in_order() -> None:
    records = [
        CheckRecord("bot", "ai.data_leakage", "insidia", COMPLETE),
        CheckRecord("bot", "ai.data_leakage", "garak", LIMITED, "garak sent only 1 prompt(s)"),
        CheckRecord("bot", "ai.data_leakage", "garak", LIMITED, "garak sent only 1 prompt(s)"),
        CheckRecord(
            "bot", "ai.data_leakage", "promptfoo", LIMITED, "promptfoo sent only 1 prompt(s)"
        ),
    ]
    result = aggregate(records)
    assert result.low_assurance is True
    assert result.assurance_reason == (
        "garak sent only 1 prompt(s); promptfoo sent only 1 prompt(s)"
    )


def test_a_limited_record_with_no_engine_name_still_flags_the_pass() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "web.ssti", "", LIMITED),
    ]
    result = aggregate(records)
    assert result.low_assurance is True
    assert result.assurance_reason == "limited"


def test_a_limited_record_without_a_reason_names_the_engine() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "web.ssti", "zap", LIMITED),
    ]
    result = aggregate(records)
    assert result.low_assurance is True
    assert result.assurance_reason == "zap was limited"


def test_info_beside_a_complete_pass_is_not_low_assurance() -> None:
    records = [
        CheckRecord("app", "web.ssti", "insidia", COMPLETE),
        CheckRecord("app", "infra.cve", "insidia", INFO, "banner only"),
    ]
    result = aggregate(records)
    status, verdict = result
    assert (status, verdict, exit_for(status, verdict)) == ("complete", "pass", 0)
    assert result.low_assurance is False

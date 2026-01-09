# WinEnum

WinEnum is a PowerShell script designed to enumerate details about a Windows system. This README provides instructions on how to use the script effectively.

## Steps to Use

1. **Download the Script**  
   Download the `WinENum.ps1` script from [here](https://github.com/Adityaminz18/WinEnum/blob/main/WinENum.ps1) and save it to your desired location.

2. **Install Dependencies**  
   Ensure you have all necessary tools or modules installed that the script might require. For example, you can install additional PowerShell modules if required:
   ```powershell
   Install-Module -Name SomeRequiredModule -Force
   ```

3. **Change the Execution Policy**  
   To run the script, update the execution policy for the current process:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

4. **Run the Script**  
   Navigate to the directory where you saved the file and execute the script:
   ```powershell
   .\WinENum.ps1
   ```

5. **Revert Execution Policy and Cleanup**  
   After running the script, change the execution policy back to its default setting and delete the script to ensure no residual files remain:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Default
   Remove-Item .\WinENum.ps1
   ```

---

## Notes

- Changing the execution policy is temporary and only applies to the current PowerShell session.
- Ensure you have the necessary permissions to run the script and modify settings.
- Only download scripts from trusted sources to avoid malicious code.

Happy system enumeration with WinEnum!
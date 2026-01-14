import React, { useState } from 'react';
import { isMobile, isTablet, isIPad13 } from 'react-device-detect';

// Device detection helpers for responsive layouts
const isTabletDevice = isTablet || isIPad13;
const isMobileOrTablet = isMobile || isTabletDevice; // Tablets use mobile layouts
import { Card, Button, Input, Badge } from './UIComponents';
import { Settings, Lock, Shield, Monitor, Bell, Network, Database, RefreshCw, Loader2, Download, Eye, EyeOff, X, ScanFace, Heart, ExternalLink, CheckCircle2 } from './Icons';
import { useWallet } from '../services/WalletContext';
import { downloadBackup } from '../services/BackupService';
import { BiometricService } from '../services/BiometricService';

interface SettingsPageProps {
   autoLockEnabled: boolean;
   autoLockMinutes: number;
   onAutoLockChange: (enabled: boolean, minutes: number) => void;
   onRescan?: () => void;
   onNavigate?: (tab: any, params?: any) => void;
}

// Need to import TabView enum or redefine for type safety if not exported easily
// Assuming it's passed down or we use string 'SEND' if enum isn't available in this file scope without import loop
// For now, let's use 'SEND' string cast as any to match App.tsx signature or import
import { TabView } from '../App';

const SettingsPage: React.FC<SettingsPageProps> = ({
   autoLockEnabled,
   autoLockMinutes,
   onAutoLockChange,
   onRescan,
   onNavigate
}) => {
   const wallet = useWallet();
   const [isRescanning, setIsRescanning] = useState(false);

   // Backup modal state
   const [showBackupModal, setShowBackupModal] = useState(false);
   const [backupPassword, setBackupPassword] = useState('');
   const [showBackupPassword, setShowBackupPassword] = useState(false);
   const [backupError, setBackupError] = useState('');
   const [isExporting, setIsExporting] = useState(false);

   // Biometric State
   const [isBioAvailable, setIsBioAvailable] = useState(false);
   const [isBioEnabled, setIsBioEnabled] = useState(false);
   const [showBioModal, setShowBioModal] = useState(false);
   const [bioPassword, setBioPassword] = useState('');
   const [showBioPassword, setShowBioPassword] = useState(false);
   const [bioError, setBioError] = useState('');
   const [isBioProcessing, setIsBioProcessing] = useState(false);

   // Change Password State
   const [showPasswordModal, setShowPasswordModal] = useState(false);
   const [currentPassword, setCurrentPassword] = useState('');
   const [newPassword, setNewPassword] = useState('');
   const [confirmPassword, setConfirmPassword] = useState('');
   const [showCurrentPassword, setShowCurrentPassword] = useState(false);
   const [showNewPassword, setShowNewPassword] = useState(false);
   const [showConfirmPassword, setShowConfirmPassword] = useState(false);
   const [passwordError, setPasswordError] = useState('');
   const [isChangingPassword, setIsChangingPassword] = useState(false);
   const [showPasswordSuccess, setShowPasswordSuccess] = useState(false);



   // Check availability
   React.useEffect(() => {
      BiometricService.isAvailable().then(setIsBioAvailable);
      setIsBioEnabled(BiometricService.isEnabled());
   }, []);

   const handleToggleBio = () => {
      if (isBioEnabled) {
         // Disable
         BiometricService.disable();
         setIsBioEnabled(false);
      } else {
         // Enable - Show Modal
         setShowBioModal(true);
         setBioError('');
         setBioPassword('');
      }
   };

   const handleEnableBio = async () => {
      if (!bioPassword) return;
      setIsBioProcessing(true);
      setBioError('');
      try {
         // Verify password first
         const isValid = await wallet.unlockWallet(bioPassword);
         if (!isValid) throw new Error('Incorrect password');

         // Enable Biometrics
         await BiometricService.enable(bioPassword);
         setIsBioEnabled(true);
         setShowBioModal(false);
         setBioPassword('');
      } catch (e: any) {
         console.error(e);
         if (e.name === 'NotAllowedError') {
            setBioError('Biometric setup cancelled');
         } else {
            setBioError(e.message || 'Failed to enable biometrics');
         }
         // If enable failed (e.g. user cancelled face id), ensure we stay disabled
         BiometricService.disable();
         setIsBioEnabled(false);
      } finally {
         setIsBioProcessing(false);
      }
   };

   const handleMinutesChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const val = parseInt(e.target.value);
      if (!isNaN(val) && val >= 0) {
         onAutoLockChange(autoLockEnabled, val);
      }
   };

   const toggleAutoLock = () => {
      onAutoLockChange(!autoLockEnabled, autoLockMinutes);
   };

   const handleRescan = async () => {
      if (isRescanning || wallet.isScanning) return;

      setIsRescanning(true);
      try {
         // Reset wallet height and start fresh scan
         await wallet.startScan(0); // Start from height 0
         if (onRescan) onRescan();
      } catch (err) {
         console.error('Rescan failed:', err);
      } finally {
         setIsRescanning(false);
      }
   };

   const handleExportBackup = async () => {
      if (!backupPassword) {
         setBackupError('Please enter your wallet password');
         return;
      }

      setIsExporting(true);
      setBackupError('');

      try {
         await downloadBackup(backupPassword);
         setShowBackupModal(false);
         setBackupPassword('');
      } catch (err: any) {
         console.error('Backup failed:', err);
         setBackupError(err.message || 'Failed to create backup');
      } finally {
         setIsExporting(false);
      }
   };

   const closeBackupModal = () => {
      setShowBackupModal(false);
      setBackupPassword('');
      setBackupError('');
   };

   const closePasswordModal = () => {
      setShowPasswordModal(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPasswordError('');
   };

   const handleChangePassword = async () => {
      if (!currentPassword || !newPassword || !confirmPassword) {
         setPasswordError('Please fill in all fields');
         return;
      }

      if (newPassword !== confirmPassword) {
         setPasswordError('New passwords do not match');
         return;
      }

      if (newPassword.length < 1) {
         setPasswordError('Password cannot be empty');
         return;
      }

      setIsChangingPassword(true);
      setPasswordError('');

      try {
         await wallet.changePassword(currentPassword, newPassword);
         closePasswordModal();
         setShowPasswordSuccess(true);
      } catch (err: any) {
         console.error('Change password failed:', err);
         setPasswordError(err.message || 'Failed to change password');
      } finally {
         setIsChangingPassword(false);
      }
   };

   // Get node info from sync status
   const nodeUrl = 'seed01.salvium.io:19081'; // Default node
   const networkHeight = wallet.syncStatus?.networkHeight || 0;
   const walletHeight = wallet.syncStatus?.walletHeight || 0;

   return (
      <>
         <div className={`animate-fade-in space-y-6 max-w-4xl mx-auto overflow-y-auto custom-scrollbar md:p-0 ${isMobileOrTablet
            ? 'h-full'
            : 'h-[calc(100vh-7rem)]'
            }`}>

            {/* Donate Section */}
            <Card className="relative overflow-hidden group">
                  <div className="absolute top-0 right-0 p-8 opacity-10 group-hover:opacity-20 transition-opacity">
                     <Heart size={120} className="text-accent-primary transform rotate-12 translate-x-10 -translate-y-10" />
                  </div>

                  <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
                     <div className="flex gap-4">
                        <div className="p-3 bg-gradient-to-br from-pink-500/20 to-rose-500/20 rounded-xl border border-pink-500/20 h-fit text-pink-400">
                           <Heart size={24} className="fill-current" />
                        </div>
                        <div>
                           <h4 className="text-white font-bold text-lg mb-1">Donate to Salvium.Tools</h4>
                           <p className="text-sm text-text-muted max-w-lg leading-relaxed">
                              This is a community funded project and donations will go to server costs. Your support helps keep the vault secure, fast, and constantly improving.
                           </p>
                        </div>
                     </div>

                     <Button
                        className="bg-gradient-to-r from-pink-600 to-rose-600 hover:from-pink-500 hover:to-rose-500 text-white border-0 shadow-lg shadow-pink-900/20 shrink-0 w-full md:w-auto"
                        onClick={() => {
                           if (onNavigate) {
                              onNavigate(TabView.SEND, {
                                 address: 'SC1siD8FEYLi4GhgYFE8YAfhYYSV6LXnpHdgJ1VSoEFEJ9s2ieV2r6EEoq43vuWTNKRXdh3Jn2WyGaqpqs9kaJHwg5x9fRm8WEf',
                                 amount: ''
                              });
                           }
                        }}
                     >
                        <Heart size={16} className="mr-2 fill-white/20" />
                        Donate Now
                     </Button>
                  </div>
            </Card>

            <div className="mb-8">
               <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-3">
                  <div className="p-2 bg-accent-primary/20 text-accent-primary rounded-xl">
                     <Settings size={28} />
                  </div>
                  Settings
               </h2>
               <p className="text-text-muted text-sm pl-14">Configure your wallet security, network, and preferences.</p>
            </div>

            {/* Security Section */}
            <div className="space-y-4">
               <h3 className="text-xs uppercase font-bold text-text-secondary tracking-wider ml-1">Security & Privacy</h3>

               <Card className="space-y-6">
                  {/* Biometric Unlock */}
                  {isBioAvailable && (
                     <>
                        <div className="flex items-center justify-between">
                           <div className="flex gap-4">
                              <div className="p-2.5 bg-bg-primary rounded-lg border border-white/5 h-fit text-text-secondary">
                                 <ScanFace size={20} />
                              </div>
                              <div>
                                 <h4 className="text-white font-medium mb-1">Unlock with Biometrics</h4>
                                 <p className="text-sm text-text-muted max-w-sm">Use biometrics to quickly unlock your wallet.</p>
                              </div>
                           </div>

                           <div className="flex items-center">
                              <button
                                 onClick={handleToggleBio}
                                 className={`w-12 h-6 rounded-full transition-colors relative ${isBioEnabled ? 'bg-accent-primary' : 'bg-white/10'}`}
                              >
                                 <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ${isBioEnabled ? 'left-7' : 'left-1'}`}></div>
                              </button>
                           </div>
                        </div>

                        <div className="h-[1px] bg-white/5 w-full"></div>
                     </>
                  )}

                  {/* Auto Lock Setting */}
                  <div className="flex items-start justify-between">
                     <div className="flex gap-4">
                        <div className="p-2.5 bg-bg-primary rounded-lg border border-white/5 h-fit text-text-secondary">
                           <Lock size={20} />
                        </div>
                        <div>
                           <h4 className="text-white font-medium mb-1">Auto-Lock Wallet</h4>
                           <p className="text-sm text-text-muted max-w-sm">Automatically lock the wallet after a period of inactivity to protect your funds.</p>

                           {autoLockEnabled && (
                              <div className="mt-4 flex items-center gap-3">
                                 <label className="text-sm text-text-secondary">Lock after</label>
                                 <div className="w-20">
                                    <Input
                                       type="number"
                                       value={autoLockMinutes}
                                       onChange={handleMinutesChange}
                                       className="py-1 px-2 text-center h-8 text-sm"
                                    />
                                 </div>
                                 <span className="text-sm text-text-secondary">minutes</span>
                              </div>
                           )}
                        </div>
                     </div>

                     <div className="flex items-center">
                        <button
                           onClick={toggleAutoLock}
                           className={`w-12 h-6 rounded-full transition-colors relative ${autoLockEnabled ? 'bg-accent-primary' : 'bg-white/10'}`}
                        >
                           <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ${autoLockEnabled ? 'left-7' : 'left-1'}`}></div>
                        </button>
                     </div>
                  </div>

                  <div className="h-[1px] bg-white/5 w-full"></div>

                  {/* Export Backup */}
                  <div className="flex items-center justify-between">
                     <div className="flex gap-4">
                        <div className="p-2.5 bg-bg-primary rounded-lg border border-white/5 h-fit text-text-secondary">
                           <Download size={20} />
                        </div>
                        <div>
                           <h4 className="text-white font-medium mb-1">Export Backup</h4>
                           <p className="text-sm text-text-muted max-w-sm">Create an encrypted backup file containing your wallet, address book, and settings.</p>
                        </div>
                     </div>
                     <Button variant="secondary" size="sm" onClick={() => setShowBackupModal(true)}>
                        <Download size={14} className="mr-1" />
                        Export
                     </Button>
                  </div>

                  <div className="h-[1px] bg-white/5 w-full"></div>

                  {/* Change Password */}
                  <div className="flex items-center justify-between">
                     <div className="flex gap-4">
                        <div className="p-2.5 bg-bg-primary rounded-lg border border-white/5 h-fit text-text-secondary">
                           <Shield size={20} />
                        </div>
                        <div>
                           <h4 className="text-white font-medium mb-1">Change Vault Password</h4>
                           <p className="text-sm text-text-muted">Update the password used to encrypt your private keys.</p>
                        </div>
                     </div>
                     <Button variant="secondary" size="sm" onClick={() => setShowPasswordModal(true)}>Update</Button>
                  </div>
               </Card>
            </div>

            {/* General Section */}
            <div className="space-y-4">
               <h3 className="text-xs uppercase font-bold text-text-secondary tracking-wider ml-1">General</h3>

               <Card className="space-y-6">
                  <div className="flex items-center justify-between">
                     <div className="flex gap-4">
                        <div className="p-2.5 bg-bg-primary rounded-lg border border-white/5 h-fit text-text-secondary">
                           <Database size={20} />
                        </div>
                        <div>
                           <h4 className="text-white font-medium mb-1">Blockchain Data</h4>
                           <p className="text-sm text-text-muted">
                              Wallet synced to block <span className="font-mono">{walletHeight.toLocaleString()}</span>
                           </p>
                           <p className="text-xs text-text-muted mt-1">Rescan wallet to find missing transactions</p>
                        </div>
                     </div>
                     <Button
                        variant="secondary"
                        size="sm"
                        onClick={handleRescan}
                        disabled={isRescanning || wallet.isScanning}
                     >
                        {isRescanning || wallet.isScanning ? (
                           <>
                              <Loader2 size={14} className="mr-1 animate-spin" />
                              Scanning...
                           </>
                        ) : (
                           <>
                              <RefreshCw size={14} className="mr-1" />
                              Rescan
                           </>
                        )}
                     </Button>
                  </div>
               </Card>
            </div>
         </div >

         {/* Backup Password Modal */}
         {
            showBackupModal && (
               <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
                  <Card className="max-w-md w-full space-y-6 relative">
                     <button
                        onClick={closeBackupModal}
                        className="absolute top-4 right-4 text-text-muted hover:text-white transition-colors"
                     >
                        <X size={20} />
                     </button>

                     <div className="text-center">
                        <div className="w-12 h-12 rounded-full bg-accent-primary/10 flex items-center justify-center text-accent-primary mx-auto mb-4">
                           <Download size={24} />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">Export Backup</h3>
                        <p className="text-text-muted text-sm">Enter your wallet password to create an encrypted backup file.</p>
                     </div>

                     <div className="space-y-4">
                        <div className="space-y-2">
                           <label className="text-xs text-text-secondary uppercase font-bold tracking-wider">Wallet Password</label>
                           <div className="relative">
                              <Input
                                 type={isMobile ? 'text' : (showBackupPassword ? 'text' : 'password')}
                                 placeholder="Enter your wallet password"
                                 value={backupPassword}
                                 onChange={(e) => setBackupPassword(e.target.value)}
                                 disabled={isExporting}
                                 style={isMobile ? { WebkitTextSecurity: showBackupPassword ? 'none' : 'disc' } : {}}
                                 autoCorrect="off"
                                 autoCapitalize="none"
                                 spellCheck="false"
                                 onKeyDown={(e) => e.key === 'Enter' && handleExportBackup()}
                              />
                              <button
                                 className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-white"
                                 onClick={() => setShowBackupPassword(!showBackupPassword)}
                              >
                                 {showBackupPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>
                        </div>

                        {backupError && <p className="text-red-400 text-xs">{backupError}</p>}

                        <div className="bg-accent-warning/10 border border-accent-warning/20 rounded-xl p-3">
                           <p className="text-xs text-accent-warning/90 leading-relaxed">
                              The backup file will be encrypted with your wallet password. Store it securely - anyone with this file and your password can access your funds.
                           </p>
                        </div>
                     </div>

                     <div className="flex gap-3">
                        <Button variant="ghost" onClick={closeBackupModal} className="flex-1" disabled={isExporting}>
                           Cancel
                        </Button>
                        <Button className="flex-[2]" onClick={handleExportBackup} disabled={isExporting}>
                           {isExporting ? (
                              <>
                                 <Loader2 size={16} className="mr-2 animate-spin" />
                                 Exporting...
                              </>
                           ) : (
                              <>
                                 <Download size={16} className="mr-2" />
                                 Download Backup
                              </>
                           )}
                        </Button>
                     </div>
                  </Card>
               </div>
            )
         }

         {/* Biometric Enable Modal */}
         {
            showBioModal && (
               <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
                  <Card className="max-w-md w-full space-y-6 relative">
                     <button
                        onClick={() => setShowBioModal(false)}
                        className="absolute top-4 right-4 text-text-muted hover:text-white transition-colors"
                     >
                        <X size={20} />
                     </button>

                     <div className="text-center">
                        <div className="w-12 h-12 rounded-full bg-accent-primary/10 flex items-center justify-center text-accent-primary mx-auto mb-4">
                           <ScanFace size={24} />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">Enable Biometric Unlock</h3>
                        <p className="text-text-muted text-sm">Enter your password to authorize biometrics setup.</p>
                     </div>

                     <div className="space-y-4">
                        <div className="space-y-2">
                           <label className="text-xs text-text-secondary uppercase font-bold tracking-wider">Wallet Password</label>
                           <div className="relative">
                              <Input
                                 type={isMobile ? 'text' : (showBioPassword ? 'text' : 'password')}
                                 placeholder="Enter your wallet password"
                                 value={bioPassword}
                                 onChange={(e) => setBioPassword(e.target.value)}
                                 disabled={isBioProcessing}
                                 style={isMobile ? { WebkitTextSecurity: showBioPassword ? 'none' : 'disc' } : {}}
                                 onKeyDown={(e) => e.key === 'Enter' && handleEnableBio()}
                                 autoCorrect="off"
                                 autoCapitalize="none"
                                 spellCheck="false"
                              />
                              <button
                                 className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-white"
                                 onClick={() => setShowBioPassword(!showBioPassword)}
                              >
                                 {showBioPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>
                        </div>

                        {bioError && <p className="text-red-400 text-xs">{bioError}</p>}
                     </div>

                     <div className="flex gap-3">
                        <Button variant="ghost" onClick={() => setShowBioModal(false)} className="flex-1" disabled={isBioProcessing}>
                           Cancel
                        </Button>
                        <Button className="flex-[2]" onClick={handleEnableBio} disabled={isBioProcessing}>
                           {isBioProcessing ? (
                              <>
                                 <Loader2 size={16} className="mr-2 animate-spin" />
                                 Verifying...
                              </>
                           ) : (
                              <>
                                 <ScanFace size={16} className="mr-2" />
                                 Enable Biometric Unlock
                              </>
                           )}
                        </Button>
                     </div>
                  </Card>
               </div>
            )
         }

         {/* Change Password Modal */}
         {
            showPasswordModal && (
               <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
                  <Card className="max-w-md w-full space-y-6 relative animate-scale-up">
                     <button
                        onClick={closePasswordModal}
                        className="absolute top-4 right-4 text-text-muted hover:text-white transition-colors"
                     >
                        <X size={20} />
                     </button>

                     <div className="text-center">
                        <div className="w-12 h-12 rounded-full bg-accent-primary/10 flex items-center justify-center text-accent-primary mx-auto mb-4">
                           <Shield size={24} />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">Change Password</h3>
                        <p className="text-text-muted text-sm">Create a new strong password for your vault.</p>
                     </div>

                     <div className="space-y-4">
                        {/* Current Password */}
                        <div className="space-y-2">
                           <label className="text-xs text-text-secondary uppercase font-bold tracking-wider">Current Password</label>
                           <div className="relative">
                              <Input
                                 type={isMobile ? 'text' : (showCurrentPassword ? 'text' : 'password')}
                                 placeholder="Enter current password"
                                 value={currentPassword}
                                 onChange={(e) => setCurrentPassword(e.target.value)}
                                 style={isMobile ? { WebkitTextSecurity: showCurrentPassword ? 'none' : 'disc' } : {}}
                                 disabled={isChangingPassword}
                                 autoCapitalize="none"
                                 autoCorrect="off"
                              />
                              <button
                                 className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-white"
                                 onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                              >
                                 {showCurrentPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>
                        </div>

                        {/* New Password */}
                        <div className="space-y-2">
                           <label className="text-xs text-text-secondary uppercase font-bold tracking-wider">New Password</label>
                           <div className="relative">
                              <Input
                                 type={isMobile ? 'text' : (showNewPassword ? 'text' : 'password')}
                                 placeholder="Enter new password"
                                 value={newPassword}
                                 onChange={(e) => setNewPassword(e.target.value)}
                                 style={isMobile ? { WebkitTextSecurity: showNewPassword ? 'none' : 'disc' } : {}}
                                 disabled={isChangingPassword}
                                 autoCapitalize="none"
                                 autoCorrect="off"
                              />
                              <button
                                 className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-white"
                                 onClick={() => setShowNewPassword(!showNewPassword)}
                              >
                                 {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>
                        </div>

                        {/* Confirm Password */}
                        <div className="space-y-2">
                           <label className="text-xs text-text-secondary uppercase font-bold tracking-wider">Confirm New Password</label>
                           <div className="relative">
                              <Input
                                 type={isMobile ? 'text' : (showConfirmPassword ? 'text' : 'password')}
                                 placeholder="Confirm new password"
                                 value={confirmPassword}
                                 onChange={(e) => setConfirmPassword(e.target.value)}
                                 style={isMobile ? { WebkitTextSecurity: showConfirmPassword ? 'none' : 'disc' } : {}}
                                 disabled={isChangingPassword}
                                 autoCapitalize="none"
                                 autoCorrect="off"
                                 onKeyDown={(e) => e.key === 'Enter' && handleChangePassword()}
                              />
                              <button
                                 className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-white"
                                 onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                              >
                                 {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                              </button>
                           </div>
                        </div>

                        {passwordError && <p className="text-red-400 text-xs animate-shake">{passwordError}</p>}
                     </div>

                     <div className="flex gap-3">
                        <Button variant="ghost" onClick={closePasswordModal} className="flex-1" disabled={isChangingPassword}>
                           Cancel
                        </Button>
                        <Button className="flex-[2]" onClick={handleChangePassword} disabled={isChangingPassword}>
                           {isChangingPassword ? (
                              <>
                                 <Loader2 size={16} className="mr-2 animate-spin" />
                                 Updating...
                              </>
                           ) : (
                              'Update Password'
                           )}
                        </Button>
                     </div>
                  </Card>
               </div>
            )
         }

         {/* Password Changed Success Modal */}
         {
            showPasswordSuccess && (
               <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
                  <Card className="max-w-sm w-full space-y-6 relative animate-scale-up text-center">
                     <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mx-auto">
                        <CheckCircle2 size={32} className="text-green-500" />
                     </div>
                     <div>
                        <h3 className="text-xl font-bold text-white mb-2">Password Changed</h3>
                        <p className="text-text-muted text-sm">Your vault password has been updated successfully.</p>
                     </div>
                     <Button
                        className="w-full"
                        onClick={() => setShowPasswordSuccess(false)}
                     >
                        Done
                     </Button>
                  </Card>
               </div>
            )
         }
      </>
   );
};

export default SettingsPage;
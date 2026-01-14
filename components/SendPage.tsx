import React, { useState, useEffect } from 'react';
import { isMobile, isBrowser, isTablet, isIPad13 } from 'react-device-detect';

// Device detection helpers for responsive layouts
const isTabletDevice = isTablet || isIPad13;
const isMobileOrTablet = isMobile || isTabletDevice; // Tablets use mobile layouts
import { Card, Button, Input, Overlay, Badge } from './UIComponents';
import { Send, User, Clock, ArrowRight, Wallet, AlertCircle, CheckCircle2, UserPlus, Search, X, Edit2, Trash2, BookOpen, Camera } from './Icons';
import { useWallet } from '../services/WalletContext';
import { formatSAL } from '../utils/format';
import QRScanner from './QRScanner';

interface SendPageProps {
  initialParams?: {
    address?: string;
    amount?: string;
    paymentId?: string;
  };
}

const SendPage: React.FC<SendPageProps> = ({ initialParams }) => {
  const wallet = useWallet();
  const [address, setAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [paymentId, setPaymentId] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentSuccess, setSentSuccess] = useState(false);
  const [txHash, setTxHash] = useState('');

  const [validationState, setValidationState] = useState<{ type: 'error' | 'warning' | null, message: string } | null>(null);
  const [actualSendAmount, setActualSendAmount] = useState<number | null>(null);

  // QR Scanner State
  const [isScannerOpen, setIsScannerOpen] = useState(false);
  const [scannerTarget, setScannerTarget] = useState<'send' | 'contact'>('send');

  // Contact State
  const [isAddContactModalOpen, setIsAddContactModalOpen] = useState(false);
  const [isAddressBookOpen, setIsAddressBookOpen] = useState(false); // Mobile Overlay
  const [editingContact, setEditingContact] = useState<any | null>(null);
  const [contactName, setContactName] = useState('');
  const [contactAddress, setContactAddress] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Handle Initial Params (e.g. from Donate button)
  useEffect(() => {
    if (initialParams) {
      if (initialParams.address) setAddress(initialParams.address);
      if (initialParams.amount) setAmount(initialParams.amount);
      if (initialParams.paymentId) setPaymentId(initialParams.paymentId);
    }
  }, [initialParams]);

  // Real-time Amount Validation
  useEffect(() => {
    const validate = async () => {
      const val = parseFloat(amount);
      if (!amount || isNaN(val) || val <= 0) {
        setValidationState(null);
        setActualSendAmount(null);
        return;
      }

      // Default fee estimate if address is missing (worst case size) or real estimate
      // Note: estimateFee in WalletService uses a fixed weight estimate (2500 bytes) currently, so address isn't critical for estimation yet
      let fee = 0.0001; // Fallback
      try {
        fee = await wallet.estimateFee(address || wallet.address, val);
      } catch (e) {
        // Keep default fallback
      }

      const available = wallet.balance.unlockedBalanceSAL || 0;
      const totalNeeded = val + fee;

      if (val > available) {
        setValidationState({
          type: 'error',
          message: 'Amount exceeds available balance'
        });
        setActualSendAmount(null);
      } else if (totalNeeded > available) {
        const remaining = Math.max(0, available - fee);
        // Only show warning if we can actually send something
        if (remaining > 0) {
          setValidationState({
            type: 'warning',
            message: 'Amount will be adjusted to cover transaction fee'
          });
          setActualSendAmount(remaining);
        } else {
          setValidationState({
            type: 'error',
            message: 'Insufficient funds to cover transaction fee'
          });
          setActualSendAmount(null);
        }
      } else {
        setValidationState(null);
        setActualSendAmount(null);
      }
    };

    const timer = setTimeout(validate, 500); // 500ms debounce
    return () => clearTimeout(timer);
  }, [amount, address, wallet.balance.unlockedBalanceSAL]);

  const handleScan = (data: string) => {
    // Basic validation or cleanup can happen here if needed
    if (scannerTarget === 'send') {
      setAddress(data);
    } else {
      setContactAddress(data);
    }
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();

    // Block if error state
    if (validationState?.type === 'error') {
      return;
    }

    if (!address || !amount) {
      setError('Please fill in all required fields');
      return;
    }

    setIsSending(true);
    setError(null);

    try {
      // Use the auto-calculated amount if in warning state, otherwise the entered amount
      const amountToSend = validationState?.type === 'warning' && actualSendAmount !== null
        ? actualSendAmount
        : parseFloat(amount);

      // When sending close to max (warning state), enable sweepAll to auto-retry with fee adjustments
      const sweepAll = validationState?.type === 'warning';
      const hash = await wallet.sendTransaction(address, amountToSend, paymentId, sweepAll);
      setTxHash(hash);
      setSentSuccess(true);
      // Update contact usage if applicable (method may not exist)
      const contact = wallet.contacts?.find(c => c.address === address);
      if (contact && typeof wallet.updateContactUsage === 'function') {
        wallet.updateContactUsage(contact.id);
      }
    } catch (err: any) {
      console.error('Variable error:', err);
      setError(err.message || 'Failed to send transaction');
    } finally {
      setIsSending(false);
    }
  };

  const resetForm = () => {
    setAddress('');
    setAmount('');
    setPaymentId('');
    setSentSuccess(false);
    setTxHash('');
    setError(null);
  };

  // Contact Management
  const selectContact = (addr: string) => {
    setAddress(addr);
    setIsAddressBookOpen(false); // Close overlay on mobile
  };

  const startEditContact = (e: React.MouseEvent, contact: any) => {
    e.stopPropagation();
    setEditingContact(contact);
    setContactName(contact.name);
    setContactAddress(contact.address);
    setIsAddContactModalOpen(true);
  };

  const handleDeleteContact = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (window.confirm('Are you sure you want to delete this contact?')) {
      wallet.removeContact(id);
    }
  };

  const openAddModal = () => {
    setEditingContact(null);
    setContactName('');
    setContactAddress('');
    setIsAddContactModalOpen(true);
  };

  const closeModal = () => {
    setIsAddContactModalOpen(false);
    setEditingContact(null);
    setContactName('');
    setContactAddress('');
  };

  const filteredContacts = wallet.contacts.filter(c =>
    c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.address.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Address Book Component (Reusable for Overlay and Desktop Sidebar)
  const AddressBookList = () => (
    <div className="flex flex-col h-full">
      <div className="relative mb-4 flex-shrink-0">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted w-[0.875rem] h-[0.875rem]" />
        <input
          type="text"
          placeholder="Search contacts..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full bg-bg-secondary border border-border-color rounded-lg py-3 pl-9 pr-4 text-sm text-white focus:outline-none focus:border-accent-primary/50 transition-colors"
        />
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 custom-scrollbar min-h-0">
        {filteredContacts.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-text-muted text-sm">No contacts found</p>
          </div>
        ) : (
          filteredContacts.map((contact) => (
            <div
              key={contact.id}
              onClick={() => selectContact(contact.address)}
              className="p-4 rounded-xl bg-bg-secondary/30 hover:bg-white/5 border border-transparent hover:border-white/5 cursor-pointer transition-all group relative pr-20"
            >
              <div className="flex justify-between items-start mb-1">
                <span className="font-semibold text-white text-base group-hover:text-accent-primary transition-colors">{contact.name}</span>
                {contact.lastSent && (
                  <span className="text-[10px] text-text-muted bg-white/5 px-2 py-1 rounded">
                    {contact.lastSent}
                  </span>
                )}
              </div>
              <p className="font-mono text-xs text-text-muted truncate mt-1">{contact.address}</p>

              {/* Action Buttons */}
              <div className="hidden md:group-hover:flex absolute right-2 top-1/2 -translate-y-1/2 gap-1 bg-black/50 p-1 rounded-lg backdrop-blur-md">
                <button
                  onClick={(e) => startEditContact(e, contact)}
                  className="p-2 hover:bg-white/10 rounded-lg text-text-muted hover:text-white transition-colors"
                  title="Edit Contact"
                >
                  <Edit2 className="w-[0.875rem] h-[0.875rem]" />
                </button>
                <button
                  onClick={(e) => handleDeleteContact(e, contact.id)}
                  className="p-2 hover:bg-red-400/10 rounded-lg text-text-muted hover:text-red-400 transition-colors"
                  title="Delete Contact"
                >
                  <Trash2 className="w-[0.875rem] h-[0.875rem]" />
                </button>
              </div>
              {/* Mobile Action Buttons */}
              <div className="flex md:hidden absolute right-2 top-1/2 -translate-y-1/2 gap-1 bg-black/50 p-1 rounded-lg backdrop-blur-md">
                <button
                  onClick={(e) => startEditContact(e, contact)}
                  className="p-2 hover:bg-white/10 rounded-lg text-text-muted hover:text-white transition-colors"
                >
                  <Edit2 className="w-[0.875rem] h-[0.875rem]" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="pt-4 border-t border-white/5 flex-shrink-0 mt-auto">
        <Button variant="secondary" className="w-full py-3" onClick={openAddModal}>
          <UserPlus className="mr-2 w-4 h-4" />
          Add New Address
        </Button>
      </div>
    </div>
  );

  return (
    <div className={`animate-fade-in md:p-0 overflow-hidden ${isMobileOrTablet
      ? 'flex flex-col h-full'
      : 'grid grid-cols-12 gap-6 h-[calc(100vh-7rem)]'
      }`}>
      {/* LEFT: Send Form */}
      <div className={`min-h-0 ${isMobileOrTablet ? 'flex-1 h-full' : 'col-span-7 h-full'}`}>
        <Card glow className="relative overflow-hidden h-full flex flex-col min-h-0">
          {/* ... existing card content ... */}
          <div className="mb-8 flex-shrink-0">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-accent-primary/10 rounded-lg text-accent-primary">
                <Send className="w-6 h-6" />
              </div>
              <h2 className="text-xl font-bold text-white">Send Assets</h2>
            </div>
            <p className="text-text-muted text-sm pl-11">Transfer SAL to another wallet securely.</p>
          </div>

          {!sentSuccess ? (
            <div className="space-y-8 flex-1 flex flex-col">
              {/* Address Input */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-text-secondary flex justify-between">
                  <span>Recipient Address</span>
                  {isMobileOrTablet && (
                    <button
                      onClick={() => setIsAddressBookOpen(true)}
                      className="text-xs text-accent-primary hover:text-accent-secondary transition-colors flex items-center"
                    >
                      <BookOpen className="mr-1 w-3 h-3" />
                      Address Book
                    </button>
                  )}
                </label>
                <div className="relative">
                  <Input
                    placeholder="SC1..."
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    className="font-mono pr-12"
                  />
                  {isMobileOrTablet && (
                    <button
                      type="button"
                      onClick={() => {
                        setScannerTarget('send');
                        setIsScannerOpen(true);
                      }}
                      className="absolute right-3 top-1/2 -translate-y-1/2 p-2 text-text-muted hover:text-accent-primary transition-colors"
                    >
                      <Camera className="w-5 h-5" />
                    </button>
                  )}
                </div>
              </div>

              {/* Amount Input */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-text-secondary font-medium">Amount</span>
                  <span className="text-text-muted">
                    Available: <span className="text-white font-mono">{formatSAL(wallet.balance.unlockedBalanceSAL || wallet.balance.unlockedBalance / 1e8)} SAL</span>
                  </span>
                </div>
                <div className="relative">
                  <Input
                    type="number"
                    placeholder="0.00"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    className="font-mono text-lg"
                    step="any"
                    min="0"
                  />
                  <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setAmount(((wallet.balance.unlockedBalance || 0) / 100000000).toString())}
                      className="text-xs text-accent-primary hover:text-white font-semibold transition-colors uppercase"
                    >
                      Max
                    </button>
                    <span className="text-text-muted font-bold text-sm pl-2 border-l border-white/10">SAL</span>
                  </div>
                </div>
                {/* Validation Message */}
                {validationState && (
                  <div className={`text-xs mt-1 ${validationState.type === 'error' ? 'text-red-400' : 'text-yellow-400'
                    } flex items-center gap-1`}>
                    <AlertCircle className="w-3 h-3" />
                    {validationState.message}
                  </div>
                )}
              </div>

              {/* Payment ID (Optional) */}
              <div className="space-y-2">
                <label className="text-sm text-text-secondary">Payment ID (Optional)</label>
                <Input
                  placeholder="Enter payment ID"
                  value={paymentId}
                  onChange={(e) => setPaymentId(e.target.value)}
                  className="font-mono"
                />
              </div>

              {/* Error/Status */}
              {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-3 text-red-100">
                  <AlertCircle className="shrink-0 text-red-500 w-5 h-5" />
                  <p className="text-sm">{error}</p>
                </div>
              )}

              {/* Send Button */}
              <div className="pt-4 mt-auto">
                <Button
                  onClick={handleSend}
                  disabled={isSending}
                  className="w-full py-4 text-lg font-bold shadow-xl shadow-accent-primary/10 hover:shadow-accent-primary/20"
                >
                  {isSending ? 'Creating Transaction...' : 'Send Assets'}
                  {!isSending && <ArrowRight className="ml-2 w-5 h-5" />}
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center flex-1 text-center py-10 animate-scale-in">
              <div className="w-20 h-20 bg-accent-success/20 rounded-full flex items-center justify-center mb-6 text-accent-success p-1">
                <div className="w-full h-full border-2 border-accent-success rounded-full flex items-center justify-center">
                  <CheckCircle2 className="w-10 h-10" />
                </div>
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Transaction Sent!</h3>
              <p className="text-text-muted mb-8 max-w-xs">{amount} SAL has been sent to the network.</p>

              {txHash && (
                <div className="w-full bg-black/20 p-4 rounded-xl border border-white/10 mb-8 max-w-md">
                  <p className="text-xs text-text-muted uppercase tracking-widest mb-2">Transaction Hash</p>
                  <p className="font-mono text-xs text-accent-primary break-all select-all">{txHash}</p>
                </div>
              )}

              <Button onClick={resetForm} variant="secondary">
                Send Another Transaction
              </Button>
            </div>
          )}
        </Card>
      </div>

      {/* RIGHT: Address Book - HIDDEN on Mobile */}
      {isBrowser && (
        <div className="col-span-5 h-full">
          <Card className="h-full flex flex-col bg-[#131320] border-white/5">
            <div className="mb-6 flex justify-between items-center flex-shrink-0">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-white/5 rounded-lg text-white">
                  <User className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-bold text-white">Address Book</h3>
              </div>
            </div>
            <AddressBookList />
          </Card>
        </div>
      )}

      {/* OVERLAY for Address Book on Mobile */}
      <Overlay isOpen={isAddressBookOpen} onClose={() => setIsAddressBookOpen(false)} title="Address Book">
        <div className="relative h-full flex flex-col">
          <button
            onClick={openAddModal}
            className="absolute bottom-24 right-4 z-10 p-3 bg-accent-primary text-white rounded-full shadow-lg hover:bg-accent-primary/90 transition-colors"
          >
            <UserPlus className="w-5 h-5" />
          </button>
          <AddressBookList />
        </div>
      </Overlay>

      {/* Add/Edit Contact Modal - Works inside Overlay or Desktop */}
      {isAddContactModalOpen && (
        <div className="fixed inset-0 z-[200] flex items-center justify-center p-4 animate-fade-in">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={closeModal}></div>
          <div className="bg-[#191928] border border-border-color rounded-2xl w-full max-w-md shadow-2xl overflow-hidden relative z-10">
            <div className="p-6 border-b border-white/5 flex justify-between items-center">
              <h3 className="font-bold text-lg text-white">
                {editingContact ? 'Edit Contact' : 'Add New Contact'}
              </h3>
              <button onClick={closeModal} className="text-text-muted hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="space-y-2">
                <label className="text-sm text-text-secondary">Name</label>
                <Input
                  placeholder="e.g. John Doe"
                  value={contactName}
                  onChange={(e) => setContactName(e.target.value)}
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm text-text-secondary">Salvium Address</label>
                <div className="relative">
                  <Input
                    placeholder="SC1..."
                    value={contactAddress}
                    onChange={(e) => setContactAddress(e.target.value)}
                    className="font-mono text-xs pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      setScannerTarget('contact');
                      setIsScannerOpen(true);
                    }}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-text-muted hover:text-accent-primary transition-colors"
                  >
                    <Camera classname="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-white/5 flex justify-end gap-3">
              <Button variant="ghost" onClick={closeModal}>Cancel</Button>
              <Button onClick={() => {
                if (editingContact) {
                  wallet.updateContact(editingContact.id, { name: contactName, address: contactAddress });
                } else {
                  wallet.addContact(contactName, contactAddress);
                }
                closeModal();
              }}>
                {editingContact ? 'Save Changes' : 'Add Contact'}
              </Button>
            </div>
          </div>
        </div>
      )}
      {isScannerOpen && (
        <QRScanner
          onScan={handleScan}
          onClose={() => setIsScannerOpen(false)}
        />
      )}
    </div>
  );
};

export default SendPage;
import cn from 'classnames';
import { useState, useCallback, useContext } from 'react';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { useNavigate } from 'react-router-dom';
import { Button } from '~components/ui/button';
import { XWalletProviderContext } from '~popup/context';
import { useConfigStore } from '~popup/store';
import { addressFormat } from '~popup/utils';
import { TwitterName } from './TwitterName';

// import matic from 'data-base64:~popup/assets/svg/matic.png';
// polygon
import pol from 'data-base64:~popup/assets/svg/logo/pol.svg';
// arbitrum
import arb from 'data-base64:~popup/assets/svg/logo/arbi.svg';
// base
import base from 'data-base64:~popup/assets/svg/logo/base.svg';
// ethereum
import eth from 'data-base64:~popup/assets/svg/logo/eth.svg';

const chains = [
  { id: 'polygon', icon: pol, name: 'Polygon' },
  { id: 'arbitrum', icon: arb, name: 'Arbitrum' },
  { id: 'base', icon: base, name: 'Base' },
  { id: 'ethereum', icon: eth, name: 'Ethereum' }
];

export default function Header() {
  const { isShowMoney, setIsShowMoney } = useConfigStore();
  const { userInfo, ethBalance, usdtBalance } = useContext(
    XWalletProviderContext
  );
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [selectedChain, setSelectedChain] = useState(chains[0]);

  const handleShowMoney = useCallback(() => {
    setIsShowMoney();
  }, []);

  const handleCopyAddress = useCallback(() => {
    console.log('copied');
  }, []);

  const handleToSend = useCallback(() => {
    navigate('/send?token=matic');
  }, []);

  const toggleDropdown = useCallback(() => {
    setIsOpen(!isOpen);
  }, [isOpen]);

  return (
    <div className="py-3 bg-white px-7 rounded-t-2xl">
      <div className="flex items-center justify-between mb-5">
        <TwitterName handle={userInfo?.username ?? 'User'} />
        <div className="flex items-center ">
          <Button
            onClick={handleToSend}
            className={cn(
              'w-20 h-8 mr-4',
              'bg-[#0F141A] border-[#0F141A] rounded-2xl hover:bg-[#67696c]',
              'flex justify-center items-center text-white hover:text-black'
            )}
          >
            Send
          </Button>
          <div className="relative">
            <button 
              onClick={toggleDropdown}
              className="flex items-center space-x-1 hover:opacity-80"
            >
              <img src={selectedChain.icon} className="object-contain w-8 h-8" alt={selectedChain.name} />
              <svg className={`w-4 h-4 transition-transform text-black${isOpen ? 'rotate-180' : ''}`} viewBox="0 0 24 24">
                <path fill="currentColor" d="M7 10l5 5 5-5H7z"/>
              </svg>
            </button>
            
            {isOpen && (
              <div className="absolute right-0 z-10 w-48 mt-2 overflow-hidden origin-top-right bg-white rounded-lg shadow-lg ring-1 ring-black ring-opacity-5">
                <div className="py-1">
                  {chains.map((chain) => (
                    <button
                      key={chain.id}
                      onClick={() => {
                        setSelectedChain(chain);
                        setIsOpen(false);
                      }}
                      className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    >
                      <img src={chain.icon} className="w-6 h-6 mr-2" alt={chain.name} />
                      <span>{chain.name}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="flex justify-between">
        <div className="flex items-center">
          <span className="mr-2 text-[#5B6A78] text-sm font-semibold">
            {addressFormat(userInfo?.accountAddress)}
          </span>

          <div className="cursor-pointer">
            <CopyToClipboard
              text={userInfo?.accountAddress}
              onCopy={handleCopyAddress}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="12"
                height="15"
                viewBox="0 0 12 15"
                fill="none"
              >
                <rect
                  x="0.5"
                  y="0.5"
                  width="8"
                  height="11"
                  fill="#F7F7F7"
                  stroke="#DCDCDC"
                />
                <rect
                  x="3.5"
                  y="3.5"
                  width="8"
                  height="11"
                  fill="#F7F7F7"
                  stroke="#DCDCDC"
                />
              </svg>
            </CopyToClipboard>
          </div>
        </div>
        <div onClick={handleShowMoney} className="cursor-pointer">
          {isShowMoney ? (
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="23"
              height="12"
              viewBox="0 0 23 12"
              fill="none"
            >
              <g clipPath="url(#clip0_2_280)">
                <path
                  d="M11.5351 0.00614766C14.3146 0.0737706 16.8649 0.866803 19.2037 2.42213C20.5553 3.31967 21.7423 4.42008 22.8059 5.66803C23.0586 5.96926 23.0644 6.05533 22.8176 6.34426C21.231 8.20697 19.3917 9.71926 17.194 10.7275C15.8013 11.3668 14.3498 11.7664 12.8279 11.9324C11.3999 12.0861 10.0013 11.9816 8.60865 11.6742C6.96915 11.3176 5.4413 10.6475 4.01335 9.72541C2.79695 8.93852 1.69807 7.99795 0.710844 6.90984C0.499296 6.67623 0.293624 6.43648 0.087952 6.20287C-0.0295748 6.06762 -0.0178221 5.95082 0.0938284 5.81557C2.1623 3.34426 4.65387 1.52459 7.69781 0.590164C8.70267 0.282787 9.73691 0.104508 10.7888 0.055328C11.0415 0.0430329 11.2941 -0.0184425 11.5351 0.0122952V0.00614766ZM11.4939 9.38115C13.1628 9.47336 14.7553 8.0041 14.7612 6.01844C14.7612 4.11885 13.2568 2.6373 11.5351 2.625C9.93082 2.6127 8.26782 3.95287 8.27369 6.03074C8.27369 7.98566 9.85443 9.44877 11.4939 9.38115ZM7.99163 2.35451C7.91524 2.30533 7.86235 2.35451 7.80359 2.3668C5.77037 3.06762 3.98984 4.18648 2.45612 5.7541C2.21519 6 2.20931 6.00615 2.44436 6.25205C3.71953 7.57992 5.20037 8.58811 6.86925 9.29508C7.22771 9.44877 7.59204 9.6209 8.01514 9.68853C6.1112 7.22951 6.12295 4.80123 7.99163 2.35451ZM15.0021 9.68238C15.0844 9.71311 15.149 9.67623 15.2137 9.65164C17.2586 8.96311 19.0392 7.80738 20.5846 6.2582C20.7668 6.07377 20.7727 5.95697 20.5846 5.77254C19.1567 4.33402 17.5231 3.2459 15.6661 2.53279C15.4487 2.45287 15.2372 2.34221 15.0021 2.33607C16.9119 4.79508 16.9237 7.22951 15.0021 9.68238Z"
                  fill="#B5B5B5"
                />
              </g>
              <defs>
                <clipPath id="clip0_2_280">
                  <rect width="23" height="12" fill="white" />
                </clipPath>
              </defs>
            </svg>
          ) : (
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="23"
              height="16"
              viewBox="0 0 23 16"
              fill="none"
            >
              <path
                d="M11.4835 13.7891C10.2691 13.7346 9.06197 13.6364 7.89082 13.2802C7.60975 13.1965 7.41516 13.2511 7.20976 13.4619C6.4422 14.2545 5.66024 15.0325 4.88188 15.8178C4.64044 16.0613 4.6008 16.0613 4.34856 15.8141C4.11793 15.5851 3.89451 15.3488 3.66389 15.1161C3.49812 14.9489 3.54137 14.818 3.69632 14.6653C4.33054 14.0364 4.95395 13.4001 5.58457 12.7676C5.80438 12.5458 5.80438 12.5458 5.53051 12.4185C4.08189 11.7278 2.76661 10.8371 1.58105 9.74642C1.09097 9.29561 0.647734 8.80845 0.19369 8.32856C-0.0657644 8.05226 -0.0621608 7.95774 0.190086 7.6778C1.66753 6.00545 3.372 4.62759 5.38277 3.65326C6.79175 2.96978 8.26919 2.52625 9.8151 2.32629C11.588 2.09725 13.343 2.24267 15.0654 2.71893C15.3501 2.79891 15.5483 2.75165 15.7645 2.52625C16.5213 1.7337 17.2996 0.966601 18.0744 0.188596C18.3266 -0.0622561 18.3591 -0.0622561 18.6041 0.18496C18.8275 0.410364 19.0473 0.643038 19.278 0.86117C19.4545 1.0284 19.4401 1.16292 19.2744 1.33015C18.6473 1.95183 18.0275 2.58078 17.4077 3.20973C17.1879 3.43149 17.1879 3.46421 17.4654 3.59509C19.2744 4.46035 20.8599 5.63463 22.2437 7.08884C22.4671 7.32515 22.6833 7.57237 22.9067 7.80868C23.0364 7.94683 23.0256 8.06317 22.9067 8.20132C20.9464 10.4481 18.6149 12.1495 15.7717 13.0875C14.6042 13.4728 13.4078 13.6982 12.179 13.7528C11.952 13.7637 11.725 13.8219 11.4943 13.7964L11.4835 13.7891ZM14.997 11.5315C15.0438 11.5315 15.069 11.5387 15.0943 11.5315C15.2276 11.4915 15.3645 11.4515 15.4979 11.4042C17.433 10.7244 19.105 9.62645 20.5896 8.21586C20.741 8.07044 20.7518 7.95774 20.5896 7.79777C19.296 6.52897 17.8257 5.53647 16.1537 4.83481C15.9051 4.72938 15.7861 4.82754 15.6348 4.9766C15.469 5.1402 15.5771 5.26017 15.66 5.39468C16.0204 5.96546 16.2654 6.58714 16.3411 7.25244C16.5105 8.76119 16.1825 10.1391 15.1339 11.2915C15.0763 11.3533 15.0078 11.4151 14.997 11.5351V11.5315ZM8.03857 4.48216C7.90524 4.424 7.83677 4.47489 7.7647 4.49671C7.253 4.65667 6.75211 4.85662 6.26563 5.08566C4.82062 5.76914 3.52335 6.67076 2.38103 7.79414C2.22247 7.95047 2.21887 8.05953 2.38103 8.20132C2.60805 8.39764 2.81706 8.61213 3.04408 8.80845C4.16838 9.79005 5.4188 10.5681 6.79535 11.1497C7.0476 11.2552 7.18093 11.1716 7.33588 11.0007C7.50164 10.8189 7.3611 10.6953 7.28183 10.5535C6.38455 8.96478 6.32329 7.34697 7.13408 5.70734C7.3575 5.2529 7.65659 4.85299 8.03496 4.48216H8.03857ZM11.4691 11.2552C11.6637 11.2443 11.8583 11.2552 12.0457 11.2224C14.1465 10.8371 15.3141 8.59396 14.4384 6.63077C14.3267 6.37628 14.2655 6.36537 14.0673 6.56896C12.7412 7.9032 11.4187 9.23744 10.0926 10.5717C9.86916 10.7971 9.88718 10.8698 10.1827 10.997C10.5935 11.1716 11.0151 11.2806 11.4655 11.2552H11.4691ZM11.4943 4.74392C11.3106 4.75119 11.1232 4.74392 10.943 4.77301C8.83134 5.11838 7.62056 7.48148 8.55747 9.41922C8.64036 9.59009 8.70522 9.63008 8.85657 9.47739C10.2151 8.10316 11.5772 6.72893 12.9394 5.36196C13.1015 5.19836 13.0547 5.12202 12.8709 5.04204C12.4313 4.84572 11.9808 4.71484 11.4907 4.74392H11.4943Z"
                fill="#484848"
              />
            </svg>
          )}
        </div>
      </div>
      <div className="mt-5 mb-6 text-3xl font-semibold">
        {isShowMoney
          ? `$ ${(Number(ethBalance) * 0.9 + Number(usdtBalance)).toFixed(5)}`
          : '**********'}
      </div>
    </div>
  );
}

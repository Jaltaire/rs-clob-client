use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use chrono::{DateTime, Utc};
use rand::Rng as _;
use rust_decimal::RoundingStrategy as RustDecimalRoundingStrategy;
use rust_decimal::prelude::ToPrimitive as _;

use crate::Result;
use crate::auth::Kind as AuthKind;
use crate::auth::state::Authenticated;
use crate::clob::Client;
use crate::clob::types::request::OrderBookSummaryRequest;
use crate::clob::types::{
    Amount, AmountInner, Order, OrderType, Side, SignableOrder, SignatureType,
};
use crate::error::Error;
use crate::types::{Address, Decimal};

pub(crate) const USDC_DECIMALS: u32 = 6;

/// Maximum number of decimal places for `size`
pub(crate) const LOT_SIZE_SCALE: u32 = 2;

/// Maximum number of decimal places for maker amounts in GTC/GTD orders.
/// Backend validates that maker_amount = price * size with full precision.
/// Using USDC precision (6 decimal places) to preserve exact calculation results.
pub(crate) const MAKER_AMOUNT_DECIMALS_RESTING: u32 = 6;

/// Maximum number of decimal places for maker amounts in FOK/FAK orders.
/// Backend error: "market buy orders maker amount supports a max accuracy of 2 decimals"
/// Immediate orders have stricter precision limits than resting orders.
pub(crate) const MAKER_AMOUNT_DECIMALS_IMMEDIATE: u32 = 2;

/// Maximum number of decimal places for taker amounts in market orders.
/// Backend constraint: "taker amount a max of 4 decimals"
pub(crate) const TAKER_AMOUNT_DECIMALS: u32 = 4;

/// Placeholder type for compile-time checks on limit order builders
#[non_exhaustive]
#[derive(Debug)]
pub struct Limit;

/// Placeholder type for compile-time checks on market order builders
#[non_exhaustive]
#[derive(Debug)]
pub struct Market;

/// Rounding strategy for market order amount calculations.
///
/// The backend requires maker amounts to have at most 4 decimal places and taker amounts
/// to have at most 4 decimal places. This enum controls how amounts are rounded to meet
/// these precision constraints.
///
/// # Example
/// ```ignore
/// client
///     .market_order()
///     .token_id(token)
///     .side(Side::Buy)
///     .amount(Amount::usdc(dec!(100)))
///     .rounding_strategy(RoundingStrategy::Down) // Use round-down (default)
///     .build()
///     .await?;
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RoundingStrategy {
    /// Round towards zero (truncate). This is the safest option to avoid overspending.
    /// For example, 10.1234 becomes 10.12 when rounding to 2 decimals.
    #[default]
    Down,
    /// Round half away from zero (standard rounding).
    /// For example, 10.125 becomes 10.13 when rounding to 2 decimals.
    HalfUp,
    /// Round away from zero.
    /// For example, 10.121 becomes 10.13 when rounding to 2 decimals.
    Up,
}

/// Used to create an order iteratively and ensure validity with respect to its order kind.
#[derive(Debug)]
pub struct OrderBuilder<OrderKind, K: AuthKind> {
    pub(crate) client: Client<Authenticated<K>>,
    pub(crate) signer: Address,
    pub(crate) signature_type: SignatureType,
    pub(crate) salt_generator: fn() -> u64,
    pub(crate) token_id: Option<U256>,
    pub(crate) price: Option<Decimal>,
    pub(crate) size: Option<Decimal>,
    pub(crate) amount: Option<Amount>,
    pub(crate) side: Option<Side>,
    pub(crate) nonce: Option<u64>,
    pub(crate) expiration: Option<DateTime<Utc>>,
    pub(crate) taker: Option<Address>,
    pub(crate) order_type: Option<OrderType>,
    pub(crate) post_only: Option<bool>,
    pub(crate) funder: Option<Address>,
    pub(crate) rounding_strategy: Option<RoundingStrategy>,
    pub(crate) _kind: PhantomData<OrderKind>,
}

impl<OrderKind, K: AuthKind> OrderBuilder<OrderKind, K> {
    /// Sets the `token_id` for this builder. This is a required field.
    #[must_use]
    pub fn token_id(mut self, token_id: U256) -> Self {
        self.token_id = Some(token_id);
        self
    }

    /// Sets the [`Side`] for this builder. This is a required field.
    #[must_use]
    pub fn side(mut self, side: Side) -> Self {
        self.side = Some(side);
        self
    }

    /// Sets the nonce for this builder.
    #[must_use]
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    #[must_use]
    pub fn expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration = Some(expiration);
        self
    }

    #[must_use]
    pub fn taker(mut self, taker: Address) -> Self {
        self.taker = Some(taker);
        self
    }

    #[must_use]
    pub fn order_type(mut self, order_type: OrderType) -> Self {
        self.order_type = Some(order_type);
        self
    }

    /// Sets the `postOnly` flag for this builder.
    #[must_use]
    pub fn post_only(mut self, post_only: bool) -> Self {
        self.post_only = Some(post_only);
        self
    }
}

impl<K: AuthKind> OrderBuilder<Limit, K> {
    /// Sets the price for this limit builder. This is a required field.
    #[must_use]
    pub fn price(mut self, price: Decimal) -> Self {
        self.price = Some(price);
        self
    }

    /// Sets the size for this limit builder. This is a required field.
    #[must_use]
    pub fn size(mut self, size: Decimal) -> Self {
        self.size = Some(size);
        self
    }

    /// Validates and transforms this limit builder into a [`SignableOrder`]
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), err(level = "warn"))
    )]
    pub async fn build(self) -> Result<SignableOrder> {
        let Some(token_id) = self.token_id else {
            return Err(Error::validation(
                "Unable to build Order due to missing token ID",
            ));
        };

        let Some(side) = self.side else {
            return Err(Error::validation(
                "Unable to build Order due to missing token side",
            ));
        };

        let Some(price) = self.price else {
            return Err(Error::validation(
                "Unable to build Order due to missing price",
            ));
        };

        if price.is_sign_negative() {
            return Err(Error::validation(format!(
                "Unable to build Order due to negative price {price}"
            )));
        }

        let fee_rate = self.client.fee_rate_bps(token_id).await?;
        let minimum_tick_size = self
            .client
            .tick_size(token_id)
            .await?
            .minimum_tick_size
            .as_decimal();

        let decimals = minimum_tick_size.scale();

        if price.scale() > minimum_tick_size.scale() {
            return Err(Error::validation(format!(
                "Unable to build Order: Price {price} has {} decimal places. Minimum tick size \
                {minimum_tick_size} has {} decimal places. Price decimal places <= minimum tick size decimal places",
                price.scale(),
                minimum_tick_size.scale()
            )));
        }

        if price < minimum_tick_size || price > Decimal::ONE - minimum_tick_size {
            return Err(Error::validation(format!(
                "Price {price} is too small or too large for the minimum tick size {minimum_tick_size}"
            )));
        }

        let Some(size) = self.size else {
            return Err(Error::validation(
                "Unable to build Order due to missing size",
            ));
        };

        if size.scale() > LOT_SIZE_SCALE {
            return Err(Error::validation(format!(
                "Unable to build Order: Size {size} has {} decimal places. Maximum lot size is {LOT_SIZE_SCALE}",
                size.scale()
            )));
        }

        if size.is_zero() || size.is_sign_negative() {
            return Err(Error::validation(format!(
                "Unable to build Order due to negative size {size}"
            )));
        }

        let nonce = self.nonce.unwrap_or(0);
        let expiration = self.expiration.unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
        let taker = self.taker.unwrap_or(Address::ZERO);
        let order_type = self.order_type.unwrap_or(OrderType::GTC);
        let post_only = Some(self.post_only.unwrap_or(false));

        if !matches!(order_type, OrderType::GTD) && expiration > DateTime::<Utc>::UNIX_EPOCH {
            return Err(Error::validation(
                "Only GTD orders may have a non-zero expiration",
            ));
        }

        if post_only == Some(true) && !matches!(order_type, OrderType::GTC | OrderType::GTD) {
            return Err(Error::validation(
                "postOnly is only supported for GTC and GTD orders",
            ));
        }

        // When buying `YES` tokens, the user will "make" `size` * `price` USDC and "take"
        // `size` `YES` tokens, and vice versa for sells.
        //
        // Backend precision requirements vary by order type:
        // - GTC/GTD (resting): Maker amounts need full precision (up to 6 decimals)
        //   Backend validates maker_amount = price * size exactly
        // - FOK/FAK (immediate): Maker amounts max 2 decimal places
        //   Backend error: "market buy orders maker amount supports a max accuracy of 2 decimals"
        // - Taker amounts: max 4 decimal places (TAKER_AMOUNT_DECIMALS)
        //
        // Context mapping for limit orders:
        // - BUY:  Maker = USDC (what user gives), Taker = shares (what user receives)
        // - SELL: Maker = shares (what user gives), Taker = USDC (what user receives)
        //
        // e.g. User submits a limit order to buy 100 `YES` tokens at $0.34.
        // This means they will take/receive 100 `YES` tokens, make/give up 34 USDC. This means that
        // the `taker_amount` is `100000000` and the `maker_amount` of `34000000`.
        let maker_decimals = match order_type {
            OrderType::GTC | OrderType::GTD => MAKER_AMOUNT_DECIMALS_RESTING,
            OrderType::FOK | OrderType::FAK | OrderType::Unknown(_) => MAKER_AMOUNT_DECIMALS_IMMEDIATE,
        };
        let (taker_amount, maker_amount) = match side {
            Side::Buy => (
                size,
                (size * price).trunc_with_scale(maker_decimals),
            ),
            Side::Sell => (
                (size * price).trunc_with_scale(TAKER_AMOUNT_DECIMALS),
                size,
            ),
            side => return Err(Error::validation(format!("Invalid side: {side}"))),
        };

        let salt = to_ieee_754_int((self.salt_generator)());

        let order = Order {
            salt: U256::from(salt),
            maker: self.funder.unwrap_or(self.signer),
            taker,
            tokenId: token_id,
            makerAmount: U256::from(to_fixed_u128(maker_amount)),
            takerAmount: U256::from(to_fixed_u128(taker_amount)),
            side: side as u8,
            feeRateBps: U256::from(fee_rate.base_fee),
            nonce: U256::from(nonce),
            signer: self.signer,
            expiration: U256::from(expiration.timestamp().to_u64().ok_or(Error::validation(
                format!("Unable to represent expiration {expiration} as a u64"),
            ))?),
            signatureType: self.signature_type as u8,
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(token_id = %token_id, side = ?side, price = %price, size = %size, "limit order built");

        Ok(SignableOrder {
            order,
            order_type,
            post_only,
        })
    }
}

impl<K: AuthKind> OrderBuilder<Market, K> {
    /// Sets the price for this market builder. This is an optional field.
    #[must_use]
    pub fn price(mut self, price: Decimal) -> Self {
        self.price = Some(price);
        self
    }

    /// Sets the [`Amount`] for this market order. This is a required field.
    #[must_use]
    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Sets the rounding strategy for market order amount calculations.
    ///
    /// The backend requires for market orders (FOK/FAK):
    /// - Maker amounts: max 2 decimal places
    /// - Taker amounts: max 4 decimal places
    ///
    /// This strategy controls how amounts are rounded to meet these constraints.
    /// Default is [`RoundingStrategy::Down`] (truncate towards zero), which is the safest
    /// option to avoid overspending or overselling.
    #[must_use]
    pub fn rounding_strategy(mut self, strategy: RoundingStrategy) -> Self {
        self.rounding_strategy = Some(strategy);
        self
    }

    // Attempts to calculate the market price from the top of the book for the particular token.
    // - Uses an orderbook depth search to find the cutoff price:
    //   - BUY + USDC: walk asks until notional >= USDC
    //   - BUY + Shares: walk asks until shares >= N
    //   - SELL + Shares: walk bids until shares >= N
    async fn calculate_price(&self, order_type: OrderType) -> Result<Decimal> {
        let token_id = self
            .token_id
            .expect("Token ID was already validated in `build`");
        let side = self.side.expect("Side was already validated in `build`");
        let amount = self
            .amount
            .as_ref()
            .expect("Amount was already validated in `build`");

        let book = self
            .client
            .order_book(&OrderBookSummaryRequest {
                token_id,
                side: None,
            })
            .await?;

        if !matches!(order_type, OrderType::FAK | OrderType::FOK) {
            return Err(Error::validation(
                "Cannot set an order type other than FAK/FOK for a market order",
            ));
        }

        let (levels, amount) = match side {
            Side::Buy => (book.asks, amount.0),
            Side::Sell => match amount.0 {
                a @ AmountInner::Shares(_) => (book.bids, a),
                AmountInner::Usdc(_) => {
                    return Err(Error::validation(
                        "Sell Orders must specify their `amount`s in shares",
                    ));
                }
            },

            side => return Err(Error::validation(format!("Invalid side: {side}"))),
        };

        let first = levels.first().ok_or(Error::validation(format!(
            "No opposing orders for {token_id} which means there is no market price"
        )))?;

        let mut sum = Decimal::ZERO;
        let cutoff_price = levels.iter().rev().find_map(|level| {
            match amount {
                AmountInner::Usdc(_) => sum += level.size * level.price,
                AmountInner::Shares(_) => sum += level.size,
            }
            (sum >= amount.as_inner()).then_some(level.price)
        });

        match cutoff_price {
            Some(price) => Ok(price),
            None if matches!(order_type, OrderType::FOK) => Err(Error::validation(format!(
                "Insufficient liquidity to fill order for {token_id} at {}",
                amount.as_inner()
            ))),
            None => Ok(first.price),
        }
    }

    /// Validates and transforms this market builder into a [`SignableOrder`]
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip(self), err(level = "warn"))
    )]
    pub async fn build(self) -> Result<SignableOrder> {
        let Some(token_id) = self.token_id else {
            return Err(Error::validation(
                "Unable to build Order due to missing token ID",
            ));
        };

        let Some(side) = self.side else {
            return Err(Error::validation(
                "Unable to build Order due to missing token side",
            ));
        };

        let amount = self
            .amount
            .ok_or_else(|| Error::validation("Unable to build Order due to missing amount"))?;

        let nonce = self.nonce.unwrap_or(0);
        let taker = self.taker.unwrap_or(Address::ZERO);

        let order_type = self.order_type.clone().unwrap_or(OrderType::FAK);
        let post_only = self.post_only;
        if post_only == Some(true) {
            return Err(Error::validation(
                "postOnly is only supported for limit orders",
            ));
        }
        let price = match self.price {
            Some(price) => price,
            None => self.calculate_price(order_type.clone()).await?,
        };

        let minimum_tick_size = self
            .client
            .tick_size(token_id)
            .await?
            .minimum_tick_size
            .as_decimal();
        let fee_rate = self.client.fee_rate_bps(token_id).await?;

        let decimals = minimum_tick_size.scale();

        // Get the rounding strategy (default: Down/truncate for safety)
        let strategy = self.rounding_strategy.unwrap_or_default();

        // Ensure that the market price is rounded to our tick size using the configured strategy
        let price = apply_rounding(price, decimals, strategy);
        if price < minimum_tick_size || price > Decimal::ONE - minimum_tick_size {
            return Err(Error::validation(format!(
                "Price {price} is too small or too large for the minimum tick size {minimum_tick_size}"
            )));
        }

        // Calculate maker and taker amounts with context-aware rounding.
        //
        // Backend precision requirements for market orders (FOK/FAK):
        // - Maker amounts: max 2 decimal places (MAKER_AMOUNT_DECIMALS_IMMEDIATE)
        // - Taker amounts: max 4 decimal places (TAKER_AMOUNT_DECIMALS)
        //
        // Context mapping:
        // - BUY:  Maker = USDC (what user gives), Taker = shares (what user receives)
        // - SELL: Maker = shares (what user gives), Taker = USDC (what user receives)
        //
        // e.g. User submits a market order to buy $100 worth of `YES` tokens at
        // the current `market_price` of $0.34. This means they will take/receive (100/0.34)
        // 294.1176(47) `YES` tokens, make/give up $100. This means that the `taker_amount` is
        // `294117600` and the `maker_amount` of `100000000`.
        //
        // e.g. User submits a market order to sell 100 `YES` tokens at the current
        // `market_price` of $0.34. This means that they will take/receive $34, make/give up 100
        // `YES` tokens. This means that the `taker_amount` is `34000000` and the `maker_amount` is
        // `100000000`.
        let raw_amount = amount.as_inner();

        let (taker_amount, maker_amount) = match (side, amount.0) {
            // Spend USDC to buy shares
            // Maker = USDC (6 decimals), Taker = shares (4 decimals)
            (Side::Buy, AmountInner::Usdc(_)) => {
                let shares = apply_rounding(raw_amount / price, TAKER_AMOUNT_DECIMALS, strategy);
                let usdc = apply_rounding(raw_amount, MAKER_AMOUNT_DECIMALS_IMMEDIATE, strategy);
                (shares, usdc)
            }

            // Buy N shares: use cutoff `price` derived from ask depth
            // Maker = USDC (6 decimals), Taker = shares (4 decimals)
            (Side::Buy, AmountInner::Shares(_)) => {
                let usdc = apply_rounding(raw_amount * price, MAKER_AMOUNT_DECIMALS_IMMEDIATE, strategy);
                let shares = apply_rounding(raw_amount, TAKER_AMOUNT_DECIMALS, strategy);
                (shares, usdc)
            }

            // Sell N shares for USDC
            // Maker = shares (6 decimals), Taker = USDC (4 decimals)
            (Side::Sell, AmountInner::Shares(_)) => {
                let usdc = apply_rounding(raw_amount * price, TAKER_AMOUNT_DECIMALS, strategy);
                let shares = apply_rounding(raw_amount, MAKER_AMOUNT_DECIMALS_IMMEDIATE, strategy);
                (usdc, shares)
            }

            (Side::Sell, AmountInner::Usdc(_)) => {
                return Err(Error::validation(
                    "Sell Orders must specify their `amount`s in shares",
                ));
            }

            (side, _) => return Err(Error::validation(format!("Invalid side: {side}"))),
        };

        // Validate that rounded amounts are not zero
        if maker_amount.is_zero() {
            return Err(Error::validation(
                "Amount too small: maker amount rounded to zero. Increase the order amount.",
            ));
        }
        if taker_amount.is_zero() {
            return Err(Error::validation(
                "Amount too small: taker amount rounded to zero. Increase the order amount.",
            ));
        }

        let salt = to_ieee_754_int((self.salt_generator)());

        let order = Order {
            salt: U256::from(salt),
            maker: self.funder.unwrap_or(self.signer),
            taker,
            tokenId: token_id,
            makerAmount: U256::from(to_fixed_u128(maker_amount)),
            takerAmount: U256::from(to_fixed_u128(taker_amount)),
            side: side as u8,
            feeRateBps: U256::from(fee_rate.base_fee),
            nonce: U256::from(nonce),
            signer: self.signer,
            expiration: U256::ZERO,
            signatureType: self.signature_type as u8,
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(token_id = %token_id, side = ?side, price = %price, amount = %amount.as_inner(), "market order built");

        Ok(SignableOrder {
            order,
            order_type,
            post_only: None,
        })
    }
}

/// Removes trailing zeros, truncates to [`USDC_DECIMALS`] decimal places, and quanitizes as an
/// integer.
fn to_fixed_u128(d: Decimal) -> u128 {
    d.normalize()
        .trunc_with_scale(USDC_DECIMALS)
        .mantissa()
        .to_u128()
        .expect("The `build` call in `OrderBuilder<S, OrderKind, K>` ensures that only positive values are being multiplied/divided")
}

/// Mask the salt to be <= 2^53 - 1, as the backend parses as an IEEE 754.
fn to_ieee_754_int(salt: u64) -> u64 {
    salt & ((1 << 53) - 1)
}

/// Apply rounding strategy to a decimal value with specified scale.
///
/// Maps our [`RoundingStrategy`] enum to the underlying `rust_decimal::RoundingStrategy`
/// and applies the rounding to the given decimal value.
fn apply_rounding(value: Decimal, decimals: u32, strategy: RoundingStrategy) -> Decimal {
    let rs = match strategy {
        RoundingStrategy::Down => RustDecimalRoundingStrategy::ToZero,
        RoundingStrategy::HalfUp => RustDecimalRoundingStrategy::MidpointAwayFromZero,
        RoundingStrategy::Up => RustDecimalRoundingStrategy::AwayFromZero,
    };
    value.round_dp_with_strategy(decimals, rs)
}

#[must_use]
#[expect(
    clippy::float_arithmetic,
    reason = "We are not concerned with precision for the seed"
)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "We are not concerned with truncation for a seed"
)]
#[expect(clippy::cast_sign_loss, reason = "We only need positive integers")]
pub(crate) fn generate_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");

    let seconds = now.as_secs_f64();
    let rand = rand::rng().random::<f64>();

    (seconds * rand).round() as u64
}

#[cfg(test)]
mod tests {
    use rust_decimal_macros::dec;

    use super::*;

    #[test]
    fn to_fixed_u128_should_succeed() {
        assert_eq!(to_fixed_u128(dec!(123.456)), 123_456_000);
        assert_eq!(to_fixed_u128(dec!(123.456789)), 123_456_789);
        assert_eq!(to_fixed_u128(dec!(123.456789111111111)), 123_456_789);
        assert_eq!(to_fixed_u128(dec!(3.456789111111111)), 3_456_789);
        assert_eq!(to_fixed_u128(Decimal::ZERO), 0);
    }

    #[test]
    #[should_panic(
        expected = "The `build` call in `OrderBuilder<S, OrderKind, K>` ensures that only positive values are being multiplied/divided"
    )]
    fn to_fixed_u128_panics() {
        to_fixed_u128(dec!(-123.456));
    }

    #[test]
    fn order_salt_should_be_less_than_or_equal_to_2_to_the_53_minus_1() {
        let raw_salt = u64::MAX;
        let masked_salt = to_ieee_754_int(raw_salt);

        assert!(masked_salt < (1 << 53));
    }

    #[test]
    fn rounding_strategy_default_is_down() {
        assert_eq!(RoundingStrategy::default(), RoundingStrategy::Down);
    }

    #[test]
    fn apply_rounding_down_should_truncate() {
        // Round down (towards zero) - truncates
        assert_eq!(
            apply_rounding(dec!(10.1234), 2, RoundingStrategy::Down),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.1299), 2, RoundingStrategy::Down),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.125), 2, RoundingStrategy::Down),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.1256), 4, RoundingStrategy::Down),
            dec!(10.1256)
        );
        assert_eq!(
            apply_rounding(dec!(10.12569), 4, RoundingStrategy::Down),
            dec!(10.1256)
        );
    }

    #[test]
    fn apply_rounding_half_up_should_round_standard() {
        // Round half up (standard rounding)
        assert_eq!(
            apply_rounding(dec!(10.125), 2, RoundingStrategy::HalfUp),
            dec!(10.13)
        );
        assert_eq!(
            apply_rounding(dec!(10.124), 2, RoundingStrategy::HalfUp),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.126), 2, RoundingStrategy::HalfUp),
            dec!(10.13)
        );
        assert_eq!(
            apply_rounding(dec!(10.12345), 4, RoundingStrategy::HalfUp),
            dec!(10.1235)
        );
        assert_eq!(
            apply_rounding(dec!(10.12344), 4, RoundingStrategy::HalfUp),
            dec!(10.1234)
        );
    }

    #[test]
    fn apply_rounding_up_should_round_away_from_zero() {
        // Round up (away from zero)
        assert_eq!(
            apply_rounding(dec!(10.121), 2, RoundingStrategy::Up),
            dec!(10.13)
        );
        assert_eq!(
            apply_rounding(dec!(10.120), 2, RoundingStrategy::Up),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.1201), 4, RoundingStrategy::Up),
            dec!(10.1201)
        );
        assert_eq!(
            apply_rounding(dec!(10.12011), 4, RoundingStrategy::Up),
            dec!(10.1202)
        );
    }

    #[test]
    fn apply_rounding_preserves_precision_when_within_limit() {
        // When value is already within precision, no change should occur
        assert_eq!(
            apply_rounding(dec!(10.12), 2, RoundingStrategy::Down),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.12), 4, RoundingStrategy::Down),
            dec!(10.12)
        );
        assert_eq!(
            apply_rounding(dec!(10.1234), 4, RoundingStrategy::Down),
            dec!(10.1234)
        );
    }

    #[test]
    fn maker_amount_decimals_resting_is_six() {
        assert_eq!(MAKER_AMOUNT_DECIMALS_RESTING, 6);
    }

    #[test]
    fn maker_amount_decimals_immediate_is_two() {
        assert_eq!(MAKER_AMOUNT_DECIMALS_IMMEDIATE, 2);
    }

    #[test]
    fn taker_amount_decimals_is_four() {
        assert_eq!(TAKER_AMOUNT_DECIMALS, 4);
    }

    #[test]
    fn maker_amount_preserves_five_decimal_precision() {
        let price = dec!(0.009);
        let size = dec!(10.85);
        let expected_maker_amount = dec!(0.09765);

        let calculated = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);

        assert_eq!(
            calculated, expected_maker_amount,
            "Maker amount calculation should preserve 5 decimal places for price={} size={}",
            price, size
        );
    }

    #[test]
    fn maker_amount_edge_cases_preserve_precision() {
        let test_cases = vec![
            (dec!(0.009), dec!(10.85), dec!(0.09765)),
            (dec!(0.001), dec!(99.99), dec!(0.09999)),
            (dec!(0.01), dec!(10.001), dec!(0.10001)),
            (dec!(0.005), dec!(20.02), dec!(0.1001)),
            (dec!(0.003), dec!(33.333), dec!(0.099999)),
            (dec!(0.99), dec!(100.00), dec!(99.00)),
            (dec!(0.001), dec!(1.00), dec!(0.001)),
            (dec!(0.999), dec!(0.01), dec!(0.00999)),
        ];

        for (price, size, expected) in test_cases {
            let calculated = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
            assert_eq!(
                calculated, expected,
                "price={} size={} expected={} got={}",
                price, size, expected, calculated
            );
        }
    }

    #[test]
    fn to_fixed_u128_preserves_precision_for_five_decimals() {
        let maker_amount = dec!(0.09765);
        let fixed = to_fixed_u128(maker_amount);
        assert_eq!(fixed, 97650, "0.09765 USDC should convert to 97650 microdollars");
    }

    #[test]
    fn to_fixed_u128_edge_cases() {
        assert_eq!(to_fixed_u128(dec!(0.09765)), 97650);
        assert_eq!(to_fixed_u128(dec!(0.09999)), 99990);
        assert_eq!(to_fixed_u128(dec!(0.10001)), 100010);
        assert_eq!(to_fixed_u128(dec!(0.099999)), 99999);
        assert_eq!(to_fixed_u128(dec!(0.000001)), 1);
        assert_eq!(to_fixed_u128(dec!(0.001)), 1000);
        assert_eq!(to_fixed_u128(dec!(0.00999)), 9990);
    }

    #[test]
    fn limit_order_buy_maker_amount_calculation() {
        let price = dec!(0.009);
        let size = dec!(10.85);

        let maker_amount = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
        let maker_amount_fixed = to_fixed_u128(maker_amount);

        assert_eq!(maker_amount, dec!(0.09765));
        assert_eq!(maker_amount_fixed, 97650);
    }

    #[test]
    fn limit_order_buy_maker_amount_with_various_prices() {
        let test_cases = vec![
            (dec!(0.001), dec!(100.00), dec!(0.1), 100_000),
            (dec!(0.002), dec!(50.00), dec!(0.1), 100_000),
            (dec!(0.005), dec!(20.00), dec!(0.1), 100_000),
            (dec!(0.009), dec!(10.85), dec!(0.09765), 97_650),
            (dec!(0.01), dec!(10.00), dec!(0.1), 100_000),
            (dec!(0.99), dec!(10.10), dec!(9.999), 9_999_000),
            (dec!(0.001), dec!(0.01), dec!(0.00001), 10),
        ];

        for (price, size, expected_maker, expected_fixed) in test_cases {
            let maker_amount = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
            let maker_fixed = to_fixed_u128(maker_amount);

            assert_eq!(
                maker_amount, expected_maker,
                "price={} size={} expected_maker={} got={}",
                price, size, expected_maker, maker_amount
            );
            assert_eq!(
                maker_fixed, expected_fixed,
                "price={} size={} expected_fixed={} got={}",
                price, size, expected_fixed, maker_fixed
            );
        }
    }

    #[test]
    fn gtc_order_uses_resting_precision() {
        let order_type = OrderType::GTC;
        let maker_decimals = match order_type {
            OrderType::GTC | OrderType::GTD => MAKER_AMOUNT_DECIMALS_RESTING,
            OrderType::FOK | OrderType::FAK | OrderType::Unknown(_) => MAKER_AMOUNT_DECIMALS_IMMEDIATE,
        };
        assert_eq!(maker_decimals, 6, "GTC orders should use 6 decimal precision");
    }

    #[test]
    fn gtd_order_uses_resting_precision() {
        let order_type = OrderType::GTD;
        let maker_decimals = match order_type {
            OrderType::GTC | OrderType::GTD => MAKER_AMOUNT_DECIMALS_RESTING,
            OrderType::FOK | OrderType::FAK | OrderType::Unknown(_) => MAKER_AMOUNT_DECIMALS_IMMEDIATE,
        };
        assert_eq!(maker_decimals, 6, "GTD orders should use 6 decimal precision");
    }

    #[test]
    fn fok_order_uses_immediate_precision() {
        let order_type = OrderType::FOK;
        let maker_decimals = match order_type {
            OrderType::GTC | OrderType::GTD => MAKER_AMOUNT_DECIMALS_RESTING,
            OrderType::FOK | OrderType::FAK | OrderType::Unknown(_) => MAKER_AMOUNT_DECIMALS_IMMEDIATE,
        };
        assert_eq!(maker_decimals, 2, "FOK orders should use 2 decimal precision");
    }

    #[test]
    fn fak_order_uses_immediate_precision() {
        let order_type = OrderType::FAK;
        let maker_decimals = match order_type {
            OrderType::GTC | OrderType::GTD => MAKER_AMOUNT_DECIMALS_RESTING,
            OrderType::FOK | OrderType::FAK | OrderType::Unknown(_) => MAKER_AMOUNT_DECIMALS_IMMEDIATE,
        };
        assert_eq!(maker_decimals, 2, "FAK orders should use 2 decimal precision");
    }

    #[test]
    fn gtc_preserves_five_decimal_maker_amount() {
        let price = dec!(0.009);
        let size = dec!(10.85);
        let maker_amount = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
        assert_eq!(maker_amount, dec!(0.09765), "GTC maker amount should preserve 5 decimal precision");
    }

    #[test]
    fn fak_truncates_maker_amount_to_two_decimals() {
        let price = dec!(0.009);
        let size = dec!(10.85);
        let maker_amount = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_IMMEDIATE);
        assert_eq!(maker_amount, dec!(0.09), "FAK maker amount should truncate to 2 decimals");
    }

    #[test]
    fn fok_truncates_maker_amount_to_two_decimals() {
        let price = dec!(0.55);
        let size = dec!(100.00);
        let maker_amount = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_IMMEDIATE);
        assert_eq!(maker_amount, dec!(55.00), "FOK maker amount should truncate to 2 decimals");

        let price2 = dec!(0.333);
        let size2 = dec!(10.00);
        let maker_amount2 = (size2 * price2).trunc_with_scale(MAKER_AMOUNT_DECIMALS_IMMEDIATE);
        assert_eq!(maker_amount2, dec!(3.33), "FOK maker amount should truncate 3.33 correctly");
    }

    #[test]
    fn order_type_precision_matrix() {
        let price = dec!(0.12345);
        let size = dec!(10.00);
        let raw_maker = size * price;
        assert_eq!(raw_maker, dec!(1.2345), "Sanity check: 10 * 0.12345 = 1.2345");

        let resting_truncated = raw_maker.trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
        assert_eq!(resting_truncated, dec!(1.2345), "Resting (6 decimal) should preserve 1.2345");

        let immediate_truncated = raw_maker.trunc_with_scale(MAKER_AMOUNT_DECIMALS_IMMEDIATE);
        assert_eq!(immediate_truncated, dec!(1.23), "Immediate (2 decimal) should truncate to 1.23");
    }

    #[test]
    fn real_world_fak_entry_order_scenario() {
        let price = dec!(0.50);
        let size = dec!(100.00);
        let raw_maker = size * price;

        let truncated = raw_maker.trunc_with_scale(MAKER_AMOUNT_DECIMALS_IMMEDIATE);
        assert_eq!(truncated, dec!(50.00), "FAK entry order: $50.00 maker amount");

        let fixed = to_fixed_u128(truncated);
        assert_eq!(fixed, 50_000_000, "FAK entry order: 50,000,000 microdollars");
    }

    #[test]
    fn real_world_gtc_hedge_order_scenario() {
        let price = dec!(0.009);
        let size = dec!(10.85);
        let raw_maker = size * price;

        let truncated = raw_maker.trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
        assert_eq!(truncated, dec!(0.09765), "GTC hedge order: $0.09765 maker amount");

        let fixed = to_fixed_u128(truncated);
        assert_eq!(fixed, 97_650, "GTC hedge order: 97,650 microdollars");
    }

    #[test]
    fn taker_amount_precision_is_four_decimals() {
        let size = dec!(10.85);
        let taker_amount = size.trunc_with_scale(TAKER_AMOUNT_DECIMALS);
        assert_eq!(taker_amount, dec!(10.85), "Taker amount should preserve 2 decimal size");

        let fractional_size = dec!(10.12345);
        let taker_amount2 = fractional_size.trunc_with_scale(TAKER_AMOUNT_DECIMALS);
        assert_eq!(taker_amount2, dec!(10.1234), "Taker amount should truncate to 4 decimals");
    }

    #[test]
    fn sell_order_maker_is_size_taker_is_usdc() {
        let price = dec!(0.50);
        let size = dec!(100.00);
        let taker_amount = (size * price).trunc_with_scale(TAKER_AMOUNT_DECIMALS);
        let maker_amount = size;

        assert_eq!(taker_amount, dec!(50.00), "Sell taker (USDC) = size * price");
        assert_eq!(maker_amount, dec!(100.00), "Sell maker (shares) = size");
    }

    #[test]
    fn buy_order_maker_is_usdc_taker_is_size() {
        let price = dec!(0.50);
        let size = dec!(100.00);
        let taker_amount = size;
        let maker_amount_gtc = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_RESTING);
        let maker_amount_fak = (size * price).trunc_with_scale(MAKER_AMOUNT_DECIMALS_IMMEDIATE);

        assert_eq!(taker_amount, dec!(100.00), "Buy taker (shares) = size");
        assert_eq!(maker_amount_gtc, dec!(50.00), "Buy maker GTC (USDC) = size * price with 6 decimals");
        assert_eq!(maker_amount_fak, dec!(50.00), "Buy maker FAK (USDC) = size * price with 2 decimals");
    }
}

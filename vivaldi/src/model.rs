use crate::{FLOAT_ZERO, coordinate::Coordinate};
use crate::vector::Vector;
use std::{time::Duration, cmp::min};
use rlp::{Decodable, Encodable};
use rand::Rng;
#[macro_use]
use log::debug;

const MIN_ERROR: f64 = 0.1;

/// The Ce algorithm value.
const ERROR_LIMIT: f64 = 0.25;

/// A Vivaldi latency model generic over N dimensional vectors.
///
/// A single Model should be instantiated for each distinct network of nodes the
/// caller participates in.
///
/// Messages exchanged between nodes in the network
/// should include the current model coordinate, and the model should be updated
/// with the measured round-trip time by calling [`observe`](crate::model::Model::observe).
#[derive(Debug)]
pub struct Model<V>
where
    V: Vector + std::fmt::Debug + Encodable + Decodable,
{
    coordinate: Coordinate<V>,
}

impl<V> Model<V>
where
    V: Vector + std::fmt::Debug + Encodable + Decodable,
{
    /// New initialises a new Vivaldi model.
    ///
    /// The model is generic over any implementation of the
    /// [`Vector`](crate::vector::Vector) trait, which should be specified when
    /// calling this method:
    ///
    /// ```
    /// use vivaldi::{Model, vector::Dimension3};
    ///
    /// let model = Model::<Dimension3>::new();
    /// ```
    pub fn new() -> Model<V> {
        Model {
            coordinate: Coordinate::new(V::default(), 2.0, 0.1),
        }
    }

    /// Observe updates the positional coordinate of the local node.
    ///
    /// This method should be called with the coordinate of the remote node and
    /// the network round-trip time measured by the caller:
    ///
    /// ```
    /// # use vivaldi::{Model, vector::Dimension3, Coordinate};
    /// # let mut model = Model::<Dimension3>::new();
    /// # let mut remote_model = Model::<Dimension3>::new();
    ///
    /// // The remote sends it's current coordinate.
    /// //
    /// // Lets pretend we got this from an RPC response:
    /// let coordinate_from_remote = remote_model.get_coordinate();
    ///
    /// // The local application issues a request and measures the response time
    /// let rtt = std::time::Duration::new(0, 42_000);
    ///
    /// // And then updates the model with the remote coordinate and rtt
    /// model.observe(&coordinate_from_remote, rtt);
    /// ```
    /// return the force applied to the coordinate
    pub fn observe(&mut self, coord: &Coordinate<V>, rtt: Duration) -> V {
        let mut rtt = rtt.as_millis() as f64;
        // Sample weight balances local and remote error (1)
        //
        // 		w = ei/(ei + ej)
        //
        let weight = self.coordinate.error() / (self.coordinate.error() + coord.error());

        // Compute relative error of this sample (2)
        //
        // 		es = | ||xi -  xj|| - rtt | / rtt
        //
        let predict_rtt = estimate_rtt(&self.coordinate, &coord).as_millis() as f64;

        /*
        */

        if rtt < 10.0 {
            debug!("Coordiante Model: real rtt is too small. Use a fixed rtt(10ms) to update.");
            rtt = 10.0
        }

        let mut relative_error = (predict_rtt - rtt).abs() / rtt;

        debug!("Coordinate Model: real rtt = {}ms, predict rtt = {}ms, rel err = {}", rtt, predict_rtt, relative_error);

        // Update weighted moving average of local error (3)
        //
        // 		ei = es × ce × w + ei × (1 − ce × w)
        //
        if relative_error > 2.0 {
            relative_error = 2.0
        }
        let mut error = relative_error * ERROR_LIMIT * weight
                + self.coordinate.error() * (1.0 - ERROR_LIMIT * weight);

        if error < MIN_ERROR {
            error = MIN_ERROR;
        }

        // Calculate the adaptive timestep (part of 4)
        //
        // 		δ = cc × w
        //
        let weighted_error = ERROR_LIMIT * weight;

        // Weighted force (part of 4)
        //
        // 		δ × ( rtt − ||xi − xj|| )
        //
        let weighted_force = weighted_error * (rtt - predict_rtt);
        if weighted_force > 100.0 {
            debug!("Coordinate: detect massive force, no update");
            return Default::default();
        }

        // Unit vector (part of 4)
        //
        // 		u(xi − xj)
        //
        let v = self.coordinate.vector().clone() - coord.vector().clone();
        let unit_v = match v.is_zero() || predict_rtt.abs() <= FLOAT_ZERO {
            true => V::new_random_unit_vec(),
            false => {
                assert!(predict_rtt.abs() > FLOAT_ZERO);
                v.clone() / predict_rtt
            }
        };

        // Calculate the new height of the local node:
        //
        //      (Old height + coord.Height) * weighted_force / diff_mag.0 + old height
        //
        let mut new_height = match v.is_zero() || predict_rtt.abs() <= FLOAT_ZERO {
            true => self.coordinate.height() + coord.height(),
            false => self.coordinate.height() + 
                (self.coordinate.height() + coord.height()) * weighted_force / predict_rtt,
        };
        if new_height < 0.0 {
            new_height = 0.0
        }

        // Update the local coordinate (4)
        //
        // 		xi = xi + δ × ( rtt − ||xi − xj|| ) × u(xi − xj)
        //
        if (predict_rtt - rtt).abs() < 10.0 {
            debug!("Coordinate Model: error is too small = {}ms, no need to update", (predict_rtt - rtt).abs());
            self.coordinate = Coordinate::new(
                self.coordinate.vector().clone(),
                error,
                self.coordinate.height(),
            );
            V::random()
        } else {
            self.coordinate = Coordinate::new(
                self.coordinate.vector().clone() + unit_v.clone() * weighted_force,
                error,
                new_height,
            );
            // return the force applied to the model
            unit_v.clone() * weighted_force
        }

        // TODO: add gravity
    }

    /// Returns the current positional coordinate of the local node.
    pub fn get_coordinate(&self) -> &Coordinate<V> {
        &self.coordinate
    }
}

/// Returns an estimate round-trip time given two coordinates.
///
/// If `A` and `B` have communicated recently, the local node can estimate the
/// latency between them with a high degree of accuracy.
///
/// If the nodes represented by `A` and `B` have never communicated the
/// estimation will still be fairly accurate given a sufficiently mature, dense
/// model.
pub fn estimate_rtt<V>(a: &Coordinate<V>, b: &Coordinate<V>) -> Duration 
where
    V: Vector + Encodable + Decodable,
{
    let diff = a.vector().clone() - b.vector().clone();

    // Apply the fixed cost height
    let diff = diff.magnitude().0 + a.height() + b.height();

    Duration::from_millis(diff as u64)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::FLOAT_ZERO;
    use crate::vector::Dimension2;
    use crate::vector::Dimension3;

    fn random_n_test(n: usize) {
        let mut real_coord = Vec::new();
        let mut model = Vec::new();

        for _ in 0..n {
            real_coord.push(Dimension3::random());
            model.push(Model::<Dimension3>::new());
        }

        for _round in 0..20 {
            for x in 0..n {
                for _trial in 0..16 {
                    let mut rng = rand::thread_rng();
                    let y = rng.gen_range(0, n);
                    if x == y {
                        continue;
                    }

                    let rtt = (real_coord[x].clone() - real_coord[y].clone()).magnitude().0;
                    let remote_coord = model[y].get_coordinate().clone();

                    model[x].observe(
                        &remote_coord, Duration::from_millis(rtt as u64),
                    );
                }
            }
        }


        let mut err_stat = Vec::new();
        for i in 0..n {
            if i == 0 {
                println!("coordinate 0 = {:?}", model[i].get_coordinate());
            }
            for j in (i + 1)..n {
                let estimate_rtt = estimate_rtt(model[i].get_coordinate(), model[j].get_coordinate()).as_millis() as f64;
                let real_rtt = (real_coord[i].clone() - real_coord[j].clone()).magnitude().0;
                if real_rtt > FLOAT_ZERO {
                    let abs_err = (estimate_rtt - real_rtt).abs() / real_rtt;
                    err_stat.push(abs_err);
                }
            }
        }
        err_stat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        for i in 1..10 {
            let err = err_stat[err_stat.len() / 10 * i];
            println!("{}% error = {}", i * 10, err);
        }

        assert!(err_stat[err_stat.len() / 2] < 0.3);
    }

    #[test] 
    fn random_10_test() {
        random_n_test(10);
    }

    #[test] 
    fn random_100_test() {
        random_n_test(100);
    }

    #[test] 
    fn random_1000_test() {
        random_n_test(1000);
    }

    /*
    #[test]
    fn independent_coords() {
        let mut a = Model::<Dimension3>::new();
        let mut b = Model::<Dimension3>::new();
        let rtt = Duration::new(1, 0);
        reciprocal_measurements!(a, b, 10, rtt);

        assert_ne!(
            a.get_coordinate().vector().0[0],
            a.get_coordinate().vector().0[1]
        );
        assert_ne!(
            a.get_coordinate().vector().0[0],
            a.get_coordinate().vector().0[2]
        )
    }
    */
}